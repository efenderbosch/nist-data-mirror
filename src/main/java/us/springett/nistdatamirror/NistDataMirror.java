/*
 * This file is part of nist-data-mirror.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package us.springett.nistdatamirror;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.AmazonS3Exception;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.util.StringUtils;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.Calendar;
import java.util.Date;

/**
 * This self-contained class can be called from the command-line. It downloads the
 * contents of NVD CPE/CVE XML and JSON data to the specified output path.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
public class NistDataMirror {

    private static final String CVE_XML_12_MODIFIED_URL = "https://nvd.nist.gov/download/nvdcve-Modified.xml.gz";
    private static final String CVE_XML_20_MODIFIED_URL =
            "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz";
    private static final String CVE_XML_12_BASE_URL = "https://nvd.nist.gov/download/nvdcve-%d.xml.gz";
    private static final String CVE_XML_20_BASE_URL = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml.gz";
    private static final String CVE_JSON_10_MODIFIED_URL =
            "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz";
    private static final String CVE_JSON_10_BASE_URL =
            "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-%d.json.gz";

    private final int startYear;
    private final int endYear;
    private final File outputDir;
    private final String s3BucketName;
    private final AmazonS3 s3 = AmazonS3ClientBuilder.defaultClient();

    public static void main(String[] args) {
        new NistDataMirror().handle();
    }

    public NistDataMirror() {
        s3BucketName = getEnvVarOrSysProp("S3_BUCKET_NAME");
        if (StringUtils.isNullOrEmpty(s3BucketName)) {
            throw new IllegalStateException("S3_BUCKET_NAME must be defined as env var or sys prop");
        }

        if (!s3.doesBucketExist(s3BucketName)) {
            throw new IllegalStateException("S3 bucket " + s3BucketName + " does not exist");
        }

        String startYear = getEnvVarOrSysProp("START_YEAR");
        if (StringUtils.isNullOrEmpty(startYear)) {
            this.startYear = 2002;
        } else {
            this.startYear = Integer.parseInt(startYear);
        }

        String endYear = getEnvVarOrSysProp("END_YEAR");
        if (StringUtils.isNullOrEmpty(endYear)) {
            this.endYear = Calendar.getInstance().get(Calendar.YEAR);
        } else {
            this.endYear = Integer.parseInt(endYear);
        }

        String outputDir = getEnvVarOrSysProp("OUTPUT_DIR");
        if (StringUtils.isNullOrEmpty(outputDir)) {
            this.outputDir = setOutputDir("/tmp");
        } else {
            this.outputDir = setOutputDir(outputDir);
        }
    }

    private String getEnvVarOrSysProp(String key) {
        String value = System.getenv(key);
        if (value != null) return value;
        return System.getProperty(key);
    }

    public void handle() {
        Date currentDate = new Date();
        System.out.println("Downloading files at " + currentDate);

        doDownload(CVE_XML_12_MODIFIED_URL);
        doDownload(CVE_XML_20_MODIFIED_URL);
        doDownload(CVE_JSON_10_MODIFIED_URL);
        for (int i = startYear; i <= endYear; i++) {
            String cve12BaseUrl = CVE_XML_12_BASE_URL.replace("%d", String.valueOf(i));
            String cve20BaseUrl = CVE_XML_20_BASE_URL.replace("%d", String.valueOf(i));
            String cveJsonBaseUrl = CVE_JSON_10_BASE_URL.replace("%d", String.valueOf(i));
            doDownload(cve12BaseUrl);
            doDownload(cve20BaseUrl);
            doDownload(cveJsonBaseUrl);
        }
    }

    public File setOutputDir(String outputDirPath) {
        File outputDir = new File(outputDirPath);
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }
        return outputDir;
    }

    private long checkHead(String cveUrl) {
        try {
            URL url = new URL(cveUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD");
            connection.connect();
            connection.getInputStream();
            return connection.getContentLengthLong();
        } catch (IOException e) {
            System.out.println("Failed to determine content length");
        }
        return 0;
    }

    private void doDownload(String cveUrl) {
        BufferedInputStream bis = null;
        BufferedOutputStream bos = null;
        File file = null;
        boolean success = false;
        try {
            URL url = new URL(cveUrl);
            String filename = url.getFile();
            filename = filename.substring(filename.lastIndexOf('/') + 1);
            file = new File(outputDir, filename).getAbsoluteFile();

            ObjectMetadata metadata = getS3Metadata(file);
            if (metadata != null && metadata.getContentLength() == checkHead(cveUrl)) {
                System.out.println("Using cached version of " + filename);
                return;
            }

            URLConnection connection = url.openConnection();
            System.out.println("Downloading " + url.toExternalForm());
            bis = new BufferedInputStream(connection.getInputStream());
            file = new File(outputDir, filename);
            bos = new BufferedOutputStream(new FileOutputStream(file));

            int i;
            while ((i = bis.read()) != -1) {
                bos.write(i);
            }
            success = true;
        } catch (IOException e) {
            System.out.println("Download failed : " + e.getLocalizedMessage());
        } finally {
            close(bis);
            close(bos);
        }
        if (file != null && success) {
            s3.putObject(s3BucketName, file.getName(), file);
        }
    }

    private ObjectMetadata getS3Metadata(File file) {
        try {
            return s3.getObjectMetadata(s3BucketName, file.getName());
        } catch (AmazonS3Exception e) {
            if (e.getStatusCode() != 404) {
                throw e;
            }
            return null;
        }
    }

    private void close(Closeable object) {
        if (object != null) {
            try {
                object.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
