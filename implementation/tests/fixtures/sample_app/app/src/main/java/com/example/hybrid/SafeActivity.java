package com.example.hybrid;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Bundle;
import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/** Test fixture: nothing in this file may be reported, although much of it looks close. */
public class SafeActivity extends Activity {

    private static final String HINT = "never call settings.setAllowFileAccess(true); here";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView web = new WebView(this);
        WebSettings settings = web.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setAllowFileAccess(false);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        // settings.setAllowFileAccess(true);
        // settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        /* web.loadUrl("javascript:old()");
           settings.setAllowUniversalAccessFromFileURLs(true); */
        boolean allowFileAccess = true;      // a local variable, not a WebView setting
        Log.d("Safe", HINT + allowFileAccess + " { not a brace }");

        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                if (url.startsWith("tel:")) {
                    try {
                        startActivity(new Intent(Intent.ACTION_DIAL, Uri.parse(url)));
                    } catch (Exception e) {
                        Log.w("Safe", "no dialer", e);
                    }
                    return true;
                }
                if (url.startsWith("geo:")) {
                    open(url);               // the helper below has its own try/catch
                    return true;
                }
                return false;
            }

            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                handler.cancel();            // proceed() would be Rule 7
            }
        });

        web.evaluateJavascript("showTotal()", null);
        web.loadUrl("https://example.com/javascript:not-a-script");
        setContentView(web);
    }

    private void open(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (Exception e) {
            Log.w("Safe", "no app for " + url, e);
        }
    }
}
