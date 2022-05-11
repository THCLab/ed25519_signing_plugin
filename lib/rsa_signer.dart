import 'package:flutter/services.dart';

class RSASigner{
  static const MethodChannel _channel = MethodChannel('ed25519_signing_plugin');
  String uuid;

  RSASigner(this.uuid);

  Future<String> getCurrentPubKey() async{
    var key = await _channel.invokeMethod("getRSAKey", {'alias': "${uuid}_0_rsa"});
    return key;
  }

  Future<String> getNextPubKey() async{
    var key = await _channel.invokeMethod("getRSAKey", {'alias': "${uuid}_1_rsa"});
    return key;
  }

  String getUuid(){
    return uuid;
  }

  Future<void> rotateForRSA() async{
    await _channel.invokeMethod("rotateForRSA", {'uuid' : uuid});
  }

  Future<String> sign(String message) async{
    var signature = await _channel.invokeMethod("signRSA", {'uuid' : uuid, 'message' : message});
    return signature;
  }
}