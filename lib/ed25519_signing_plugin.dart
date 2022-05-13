
import 'dart:async';

import 'package:ed25519_signing_plugin/ed25519_signer.dart';
import 'package:ed25519_signing_plugin/rsa_signer.dart';
import 'package:flutter/services.dart';
import 'package:uuid/uuid.dart';

import 'exceptions.dart';

class Ed25519SigningPlugin {
  static const MethodChannel _channel = MethodChannel('ed25519_signing_plugin');



  ///Initializes the Ed25519 signer object, which will allow the user to generate keys,
  ///rotate them and delete them.
  static Future<Ed25519Signer> establishForEd25519() async{
    String uuid = const Uuid().v4().toString();
    await _channel.invokeMethod('establishForEd25519', {'uuid' : uuid});
    return Ed25519Signer(uuid);
  }

  ///Returns the Ed25519 signer object from given uuid
  static Ed25519Signer getEd25519SignerFromUuid(String uuid){
    return Ed25519Signer(uuid);
  }


  ///Returns the RSA signer object from given uuid
  static RSASigner getRSASignerFromUuid(String uuid){
    return RSASigner(uuid);
  }

  ///Initializes the RSA signer object, which will allow the user to generate keys,
  ///rotate them and delete them.
  static Future<RSASigner> establishForRSA() async{
    String uuid = const Uuid().v4().toString();
    await _channel.invokeMethod('establishForRSA', {'uuid' : uuid});
    return RSASigner(uuid);
  }

  ///Deletes the keys established by signer with particular uuid
  static Future<void> cleanUp(String uuid) async{
    await _channel.invokeMethod('cleanUp', {'uuid' : uuid});
  }


  /** SharedPref methods **/

  ///Writes provided data under provided key in shared preferences. Data is encrypted using AES.
  ///Works only if the device has a secure screen lock set, otherwise throws an exception. Returns true if data is successfully saved.
  static Future<bool> writeData(String key, String data) async {
    bool isDeviceSecure = await _channel.invokeMethod("checkIfDeviceSecure");
    if (isDeviceSecure) {
      var result = await _channel
          .invokeMethod('writeData', {'key': key, 'data': data});
      if (result == true) {
        return true;
      } else {
        throw SharedPreferencesException(
            'Writing to shared preferences failed. Consider reopening or reinstalling the app.');
      }
    }
    throw DeviceNotSecuredException(
        'Secure lock on this device is not set up. Consider setting a pin or pattern.');
  }

  ///Reads data saved under provided key from shared preferences.
  ///Works only if the device has a secure screen lock set, otherwise throws an exception. Returns data if it is successfully read.
  static Future<dynamic> readData(String key) async {
    bool isDeviceSecure = await _channel.invokeMethod("checkIfDeviceSecure");
    if (isDeviceSecure) {
      var data = await _channel.invokeMethod('readData', {'key': key});
      if (data != false) {
        return data.toString().substring(
            data.toString().indexOf(':') + 1, data.toString().length);
      } else {
        throw NoKeyInStorageException(
            'No such key found in phone storage. Consider saving it to storage before reading.');
      }
    }
    throw DeviceNotSecuredException(
        'Secure lock on this device is not set up. Consider setting a pin or pattern.');
  }

  ///Deletes data saved under provided key from shared preferences.
  ///Works only if the device has a secure screen lock set, otherwise throws an exception. Returns true if data is successfully deleted.
  static Future<bool> deleteData(String key) async {
    bool isDeviceSecure = await _channel.invokeMethod("checkIfDeviceSecure");
    if (isDeviceSecure) {
      var result = await _channel.invokeMethod('deleteData', {'key': key});
      if (result != false) {
        return true;
      } else {
        throw SharedPreferencesException(
            'Writing to shared preferences failed. Consider reopening or reinstalling the app.');
      }
    }
    throw DeviceNotSecuredException(
        'Secure lock on this device is not set up. Consider setting a pin or pattern.');
  }

  ///Edits data under provided key in shared preferences. Data is encrypted using AES.
  ///Works only if the device has a secure screen lock set, otherwise throws an exception. Returns true if data is successfully saved.
  static Future<bool> editData(String key, String data) async {
    bool isDeviceSecure = await _channel.invokeMethod("checkIfDeviceSecure");
    if (isDeviceSecure) {
      var result = await _channel
          .invokeMethod('editData', {'key': key, 'data': data});
      if (result == true) {
        return true;
      } else {
        throw SharedPreferencesException(
            'Writing to shared preferences failed. Consider reopening or reinstalling the app.');
      }
    }
    throw DeviceNotSecuredException(
        'Secure lock on this device is not set up. Consider setting a pin or pattern.');
  }

}
