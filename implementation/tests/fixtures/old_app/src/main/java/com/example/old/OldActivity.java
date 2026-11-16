package com.example.old;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;

/** Test fixture: minSdk 16, so Rule 5 is reported but must not be fixed automatically. */
public class OldActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView web = new WebView(this);
        web.loadUrl("javascript:init()");
        setContentView(web);
    }
}
