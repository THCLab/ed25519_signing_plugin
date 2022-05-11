import 'package:flutter/services.dart';

class RSASigner{
  static const MethodChannel _channel = MethodChannel('ed25519_signing_plugin');
  String uuid;

  RSASigner(this.uuid);

  Future<String> getPubKey() async{
    var key = await _channel.invokeMethod("getRSAKey", {'alias': "${uuid}_rsa"});
    return key;
  }

  String getUuid(){
    return uuid;
  }
}