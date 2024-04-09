Future<JsObject> _getRSAObject() async{
  Completer<JsObject> completer = Completer();
  context.callMethod('generateRSAKeyPair');
  js.context['flutterJsBridge'] = js.JsObject.jsify({
    'sendStringToFlutter': ( message) {
      // Do something with the received message
      completer.complete(message);
    }
  });
  return completer.future;
}
