package com.example.hybrid

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.net.http.SslError
import android.os.Bundle
import android.webkit.SslErrorHandler
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient

/** Test fixture: the Kotlin forms of the rules. */
class KotlinActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val web = WebView(this)
        web.settings.apply {
            javaScriptEnabled = true
            mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW   // Rule 3
            allowFileAccess = true                                      // Rule 4
            allowUniversalAccessFromFileURLs = true                     // Rule 6
        }
        web.settings.allowFileAccessFromFileURLs = true                 // Rule 6

        // Rule 1: no shouldOverrideUrlLoading
        web.webViewClient = object : WebViewClient() {
            override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
                handler?.proceed()                                      // Rule 7
            }
        }
        val name = "total"
        web.loadUrl("javascript:show('$name')")                         // Rule 5
        setContentView(web)
    }

    /** Rule 2: startActivity without try/catch. */
    class LinkClient : WebViewClient() {
        override fun shouldOverrideUrlLoading(view: WebView, url: String): Boolean {
            if (url.startsWith("mailto:")) {
                view.context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                return true
            }
            return false
        }
    }
}
