package de.hernan.qu1ckr00t;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.text.Editable;
import android.text.Selection;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.method.ScrollingMovementMethod;
import android.text.style.StyleSpan;
import android.view.View;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class MainActivity extends Activity {

    Button rootButton;
    String pocPath;
    String magiskInstPath;
    String magiskPath;
    TextView textView;
    ScrollView scrollView;
    TextView deviceInfo;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        rootButton = (Button) findViewById(R.id.button);
        textView = (TextView)findViewById(R.id.textView2);
        deviceInfo = (TextView)findViewById(R.id.deviceInfo);
        scrollView = (ScrollView)findViewById(R.id.scrollView2);

        SpannableStringBuilder ssb = new SpannableStringBuilder();
        addLabel(ssb, "设备", String.format("%s (Android %s)", DeviceInfo.getDeviceName(), DeviceInfo.getAndroidVersion()));
        addLabel(ssb, "内核", String.format("%s (%s)", DeviceInfo.getKernelVersion(), DeviceInfo.getDeviceArchitecture()));
        addLabel(ssb, "补丁", DeviceInfo.getAndroidPatchLevel());
        addLabel(ssb, "指纹", DeviceInfo.getBuildFingerprint());

        deviceInfo.setText(ssb);

        textView.setMovementMethod(new ScrollingMovementMethod());

        rootButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                rootButton.setText("正在获取 Root 权限...");
                addStatus("开始 Root 进程");
                rootButton.setClickable(false);
                rootButton.getBackground().setColorFilter(Color.GRAY, PorterDuff.Mode.MULTIPLY);
                new POCTask().execute();

            }
        });
    }

    private static void addLabel(SpannableStringBuilder ssb, String label, String text)
    {
        int start = ssb.length();
        ssb.append(label + ": ");
        ssb.setSpan(new StyleSpan(android.graphics.Typeface.BOLD), start, ssb.length(), Spanned.SPAN_INCLUSIVE_EXCLUSIVE);
        ssb.append(text + "\n");
    }

    private void addStatus(String status)
    {
        textView.append(status + "\n");

        // auto scroll: https://stackoverflow.com/a/34866634/5768099
        int bottom = textView.getBottom() + scrollView.getPaddingBottom();
        int sy = scrollView.getScrollY();
        int sh = scrollView.getHeight();
        int delta = bottom - (sy + sh);

        scrollView.smoothScrollBy(0, delta);
    }

    private class POCTask extends AsyncTask<String, String, Boolean> {
        protected Boolean doInBackground(String... programs) {
            extractPoc();
            extractMagisk();

            try {
                String [] args = {pocPath, "shell_exec", magiskInstPath + " " + magiskPath};
                if(!executeNativeCode(args)) {
                    publishProgress("获取 Root 权限时本地执行失败");
                    return false;
                }

                return true;
            } catch(IOException ie) {
                addStatus(ie.toString());
                return false;
            } catch(InterruptedException io) {
                addStatus(io.toString());
                return false;
            }
        }

        private void extractPoc()
        {
            InputStream poc = getResources().openRawResource(R.raw.poc);
            File pocDir = getApplicationContext().getFilesDir();
            File pocFile = new File(pocDir, "do_root");
            pocPath = pocFile.getPath();
            publishProgress("从 APK 中提取 poc 原生 root 代码...");
            copyFile(poc, pocFile.getPath());
            pocFile.setExecutable(true);
        }

        private void extractMagisk()
        {
            publishProgress("提取 Magiskinit64...");

            InputStream magisk = getResources().openRawResource(R.raw.magiskinit64);
            File fileDir = getApplicationContext().getFilesDir();
            // XXX: hardcoded to 64 bit
            File magiskFile = new File(fileDir, "magiskinit64");
            magiskPath = magiskFile.getPath();
            copyFile(magisk, magiskPath);
            magiskFile.setExecutable(true);

            publishProgress("提取 Magisk_install...");

            InputStream magiskInst = getResources().openRawResource(R.raw.magisk_install);
            File magiskInstFile = new File(fileDir, "magisk_install");
            magiskInstPath = magiskInstFile.getPath();
            copyFile(magiskInst, magiskInstPath);
            magiskInstFile.setExecutable(true);
        }

        private boolean executeNativeCode(String [] args) throws IOException, InterruptedException {
            publishProgress("执行原生 Root 二进制文件...");
            Process nativeApp = Runtime.getRuntime().exec(args);

            BufferedReader reader = new BufferedReader(new InputStreamReader(nativeApp.getInputStream()));

            String str;
            while((str=reader.readLine())!=null) {
                publishProgress("[poc] " + str);
            }

            reader.close();

            // Waits for the command to finish.
            nativeApp.waitFor();
            return nativeApp.exitValue() == 0;
        }

        protected void onProgressUpdate(String... updates) {
            addStatus(updates[0]);
        }

        protected void onPostExecute(Boolean result) {
            if (!result) {
                addStatus("Root 失败 :(\n");

                rootButton.setText("Root");
                rootButton.setClickable(true);
                rootButton.getBackground().setColorFilter(null);
            } else {
                addStatus("享受您已获得 Root 权限的设备吧！");
                rootButton.setText("已获得 Root");
            }
        }
    }

    private static void copyFile(InputStream in, String localPath) {
        try {
            FileOutputStream out = new FileOutputStream(localPath);
            int read;
            byte[] buffer = new byte[4096];
            while ((read = in.read(buffer)) > 0) {
                out.write(buffer, 0, read);
            }
            out.close();
            in.close();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
