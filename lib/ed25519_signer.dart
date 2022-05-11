import 'package:flutter/services.dart';

class Ed25519Signer{
  static const MethodChannel _channel = MethodChannel('ed25519_signing_plugin');
  String uuid;

  Ed25519Signer(this.uuid);

  Future<String> getCurrentPubKey() async{
    var key = await _channel.invokeMethod("readData", {'key': "${uuid}_0_pub"});
    return key;
  }

  Future<String> getNextPubKey() async{
    var key = await _channel.invokeMethod("readData", {'key': "${uuid}_1_pub"});
    return key;
  }

  String getUuid(){
    return uuid;
  }

  Future<void> rotateForEd25519() async{
    await _channel.invokeMethod("rotateForEd25519", {'uuid' : uuid});
  }

  Future<String> sign(String message) async{
    var signature = await _channel.invokeMethod("signEd25519", {'uuid' : uuid, 'message' : message});
    return signature;
  }

}