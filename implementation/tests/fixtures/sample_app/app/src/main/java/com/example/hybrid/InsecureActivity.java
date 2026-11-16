package com.example.hybrid;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Bundle;
import android.webkit.SslErrorHandler;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/** Test fixture: every HybridPatcher rule is violated in this file. */
public class InsecureActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView web = new WebView(this);
        WebSettings settings = web.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);   // Rule 3
        settings.setAllowFileAccess(true);                                      // Rule 4
        settings.setAllowFileAccessFromFileURLs(true);                          // Rule 6
        settings.setAllowUniversalAccessFromFileURLs(true);                     // Rule 6

        // Rule 1: this client has no shouldOverrideUrlLoading
        web.setWebViewClient(new WebViewClient() {
            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                handler.proceed();                                              // Rule 7
            }
        });

        web.loadUrl("https://example.com");
        web.loadUrl("javascript:showTotal()");                                  // Rule 5
        setContentView(web);
    }

    /** Rule 2: startActivity without try/catch. */
    static class LinkClient extends WebViewClient {
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            if (url.startsWith("mailto:")) {
                Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
                view.getContext().startActivity(intent);
                return true;
            }
            return false;
        }
    }
}
