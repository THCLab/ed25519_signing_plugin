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

  static Future<String> getUuid() async{
    var uuid = await _channel.invokeMethod("getUuid");
    return uuid;
  }

  static Ed25519Signer getSignerFromUuid(String uuid){
    return Ed25519Signer(uuid);
  }


}