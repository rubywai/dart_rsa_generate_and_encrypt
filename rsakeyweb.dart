
import 'package:flutter/material.dart';
import 'dart:js' as js;

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: Text('RSA Key Generator Demo'),
        ),
        body: Center(
          child: ElevatedButton(
            onPressed: () {
              js.context.callMethod('eval', ["""
                var script = document.createElement('script');
                script.src = 'rsa-key-generator.js';
                document.head.append(script);
              """]);

              // Call the JavaScript function directly
              var result = js.context.callMethod('generateRSAKeyPair');
              String privateKey = result['privateKey'];
              String publicKey = result['publicKey'];
              print('Private Key: ${privateKey.replaceAll(RegExp(r'-----[^-]+-----'), '')}');
              print('Public Key: $publicKey');
            },
            child: Text('Generate RSA Key Pair'),
          ),
        ),
      ),
    );
  }
}
// Load forge library from CDN
