package com.thc.ed25519_signing_plugin

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.widget.Toast
import androidx.annotation.NonNull

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.Sign
import com.goterl.lazysodium.utils.Key
import com.goterl.lazysodium.utils.KeyPair
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.PluginRegistry
import java.math.BigInteger
import java.security.*
import java.security.cert.Certificate
import java.security.KeyPair as JavaKeyPair
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.security.auth.x500.X500Principal
import kotlin.properties.Delegates

/** Ed25519SigningPlugin */
public class Ed25519SigningPlugin: FlutterPlugin, MethodCallHandler, ActivityAware, PluginRegistry.ActivityResultListener {
  /// The MethodChannel that will the communication between Flutter and native Android
  ///
  /// This local reference serves to register the plugin with the Flutter Engine and unregister it
  /// when the Flutter Engine is detached from the Activity
  private lateinit var channel : MethodChannel
  private lateinit var context: Context
  private lateinit var activity: Activity
  private lateinit var keyPairRSA: JavaKeyPair
  var lazySodium = LazySodiumAndroid(SodiumAndroid())
  private lateinit var keyguardManager: KeyguardManager
  private var isDeviceSecure by Delegates.notNull<Boolean>()
  private var dataToSign: String = ""
  private var dataSignature: String = ""
  private lateinit var pendingResult: Result
  private lateinit var signatureResult: String

  override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "ed25519_signing_plugin")
    channel.setMethodCallHandler(this)
    context = flutterPluginBinding.applicationContext
    keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    checkIfDeviceSecure()

    if(!checkAESKeyExists()){
      createAESKey()
    }
  }

  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
    if(call.method == "signEd25519"){
      val message = call.argument<String>("message")
      var pub = readData(ED_PUBLIC_KEY_1_ALIAS)
      var priv = readData(ED_PUBLIC_KEY_1_ALIAS)
      var kp = KeyPair(Key.fromBase64String(pub as String?),Key.fromBase64String(priv as String?))
      var signature = message?.let { signEd25519(kp, it, lazySodium) }
      result.success(signature)
    }else if(call.method == "signRSA"){
      this.pendingResult = result
      val data = call.argument<String>("message")
      if (data != null) {
        dataToSign = data
        val intent: Intent? = keyguardManager.createConfirmDeviceCredentialIntent("Keystore Sign And Verify",
          "In order to sign the data you need to confirm your identity. Please enter your pin/pattern or scan your fingerprint")
        if (intent != null) {
          activity.startActivityForResult(intent, REQUEST_CODE_FOR_CREDENTIALS)
        }
      }else{
        result.error("UNAVAILABLE", "Data cannot be null!", null)
      }
    }else if(call.method == "checkIfDeviceSecure"){
      val getResult = checkIfDeviceSecure()
      if (getResult){
        result.success(true)
      }else{
        result.success(false)
      }
    }else if (call.method == "writeData"){
      val key = call.argument<String>("key")
      val dataToWrite = call.argument<String>("data")
      if (key != null && dataToWrite != null) {
        writeData(key, dataToWrite)
        result.success(true)
      }else{
        result.success(false)
      }
    } else if (call.method == "readData"){
      val key = call.argument<String>("key")
      if(key != null){
        val userData = readData(key)
        if(userData != false){
          result.success(userData)
        }else{
          result.success(false)
        }
      }
    }
    else if (call.method == "deleteData"){
      val key = call.argument<String>("key")
      if (key != null) {
        deleteData(key)
        result.success(true)
      }else{
        result.success(false)
      }
    }
    else if (call.method == "editData"){
      val key = call.argument<String>("key")
      val dataToWrite = call.argument<String>("data")
      if (key != null && dataToWrite != null) {
        editData(key, dataToWrite)
        result.success(true)
      }else{
        result.success(false)
      }
    }else if(call.method == "establishForEd25519"){
      val uuid = call.argument<String>("uuid")
      if (uuid != null) {
        try {
          createEd25519Key(uuid)
          createSecondEd25519Key(uuid)
          result.success(true)
        }catch (e: Exception){
          result.success(false)
        }
      }
    }else {
      result.notImplemented()
    }
  }

  override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }

  private fun checkIfDeviceSecure() : Boolean{
    return if (!keyguardManager.isDeviceSecure) {
      Toast.makeText(context, "Secure lock screen hasn't set up.", Toast.LENGTH_LONG).show()
      isDeviceSecure = false
      false
    }else{
      isDeviceSecure = true
      true
    }
  }


  /** Ed25519 functions */
  fun signEd25519(keyPair: KeyPair, text: String, lazySodium: LazySodiumAndroid): String? {
    val messageBytes: ByteArray = lazySodium.bytes(text)
    val signedMessage: ByteArray = lazySodium.randomBytesBuf(Sign.BYTES)
    val res: String? = lazySodium.cryptoSignDetached(
      text, keyPair.secretKey
    )
    if (res != null) {
    }
    return res
  }

//  fun verifyEd25519(
//    key : String,
//    message: String,
//    lazySodium: LazySodiumAndroid,
//    signature: String
//  ): Boolean {
//    return lazySodium.cryptoSignVerifyDetached(
//      signature, message, Key.fromBase64String(key)
//    )
//  }

  fun getPublicKey(keyPair: KeyPair) = Base64.encodeToString(keyPair.publicKey.asBytes, Base64.NO_WRAP)
  fun getPrivateKey(keyPair: KeyPair) = Base64.encodeToString(keyPair.secretKey.asBytes, Base64.NO_WRAP)


//  /** RSA functions */
//  //FUNCTION TO VERIFY DATA READ FROM SHARED PREFERENCES
//  private fun verifyRSA(dataToVerify: String?) : Boolean {
//    if (isDeviceSecure) {
//      val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
//        load(null)
//      }
//      val signatureFromUser = dataToVerify?.subSequence(0, dataToVerify.indexOf(":")).toString()
//      val dataFromUser =
//        dataToVerify?.subSequence(dataToVerify.indexOf(":") + 1, dataToVerify.length).toString()
//      val certificate: Certificate? = keyStore.getCertificate(RSA_KEY_ALIAS)
//
//      if (certificate != null) {
//        val signature: ByteArray = Base64.decode(signatureFromUser, Base64.DEFAULT)
//        val isValid: Boolean = Signature.getInstance("SHA256withRSA").run {
//          initVerify(certificate)
//          update(dataFromUser.toByteArray())
//          verify(signature)
//        }
//        return isValid
//      } else {
//        return false
//      }
//    } else {
//      return false
//    }
//  }


  /** Shared Preferences functions */
  fun writeData(key: String, data: String){
    try{
      val encryptedData = encrypt(data)
      val sharedPref = activity.getPreferences(Context.MODE_PRIVATE) ?: return
      with (sharedPref.edit()) {
        putString(key, encryptedData)
        apply()
      }
    }catch (e: Exception){
      Toast.makeText(context, "Something went wrong, try again!", Toast.LENGTH_SHORT).show()
    }
  }

  private fun readData(key: String): Any {
    val sharedPref = activity.getPreferences(Context.MODE_PRIVATE)
    val textToRead : String? = sharedPref.getString(key, null)
    if(textToRead.isNullOrEmpty()){
      return false
    }else{
      val userData = decrypt(textToRead)
      if(userData != null){
        return userData
      }
      return false
    }
  }

  private fun deleteData(key: String){
    try{
      val sharedPref = activity.getPreferences(Context.MODE_PRIVATE) ?: return
      with (sharedPref.edit()) {
        remove(key)
        apply()
      }
    }catch (e: Exception){
      Toast.makeText(context, "Something went wrong, try again!", Toast.LENGTH_SHORT).show()
    }
  }

  private fun editData(key: String, data: String){
    try{
      val encryptedStringConcat = encrypt(data)
      val sharedPref = activity.getPreferences(Context.MODE_PRIVATE) ?: return
      with (sharedPref.edit()) {
        putString(key, encryptedStringConcat)
        apply()
      }
    }catch (e: Exception){
      Toast.makeText(context, "Something went wrong, try again!", Toast.LENGTH_SHORT).show()
    }
  }

  /** Key generation functions */
  //FUNCTION TO CREATE AES KEY FOR ENCRYPTION AND DECRYPTION
  private fun createAESKey() {
    val keyGenerator = KeyGenerator.getInstance(
      KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE
    )
    keyGenerator.init(
      KeyGenParameterSpec.Builder(
        ANDROID_AES_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
      )
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .build()
    )
    keyGenerator.generateKey()
  }

  //FUNCTION TO CHECK IF KEY FOR ENCRYPTION AND DECRYPTION EXISTS
  private fun checkAESKeyExists() :Boolean{
    val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
      load(null)
    }
    //We get the aes key from the keystore if they exists
    val secretKey = keyStore.getKey(ANDROID_AES_ALIAS, null) as SecretKey?
    return secretKey != null
  }

  private fun createEd25519Key(uuid: String){
    val keyPair by lazy {
      lazySodium.cryptoSignKeypair().apply {
        val newKeyPair = this
      }
    }
    var pub = getPublicKey(keyPair)
    writeData("${uuid}_0_pub", pub)
    var priv = getPrivateKey(keyPair)
    writeData("${uuid}_0_priv", priv)
  }

  private fun createSecondEd25519Key(uuid: String){
    val keyPair by lazy {
      lazySodium.cryptoSignKeypair().apply {
        val newKeyPair = this
      }
    }
    var pub = getPublicKey(keyPair)
    writeData("${uuid}_0_pub", pub)
    var priv = getPrivateKey(keyPair)
    writeData("${uuid}_0_priv", priv)
  }

//  private fun checkEd25519KeyExists() : Boolean{
//    return readData(ED_PUBLIC_KEY_1_ALIAS) != false
//  }

  //FUNCTION TO GENERATE KEY TO SIGN/VERIFY DATA
  private fun createRSAKey(uuid: String) {
    if(isDeviceSecure){
      val startDate = GregorianCalendar()
      val endDate = GregorianCalendar()
      endDate.add(Calendar.YEAR, 1)

      val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)

      val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder("${uuid}_rsa",
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY).run {
        setCertificateSerialNumber(BigInteger.valueOf(777))
        setCertificateSubject(X500Principal("CN=$RSA_KEY_ALIAS"))
        setDigests(KeyProperties.DIGEST_SHA256)
        setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        setCertificateNotBefore(startDate.time)
        setCertificateNotAfter(endDate.time)
        setUserAuthenticationRequired(true)
        setUserAuthenticationValidityDurationSeconds(10)
        build()
      }
      keyPairGenerator.initialize(parameterSpec)
      keyPairRSA = keyPairGenerator.genKeyPair()
    }
  }

//  //FUNCTION TO CHECK IF SIGN/VERIFY KEY EXISTS
//  private fun checkRSAKeyExists(): Boolean {
//    if(isDeviceSecure){
//      val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
//        load(null)
//      }
//      val privateKey: PrivateKey? = keyStore.getKey(RSA_KEY_ALIAS, null) as PrivateKey?
//      val publicKey: PublicKey? = keyStore.getCertificate(RSA_KEY_ALIAS)?.publicKey
//
//      return privateKey != null && publicKey != null
//    }else{
//      return false
//    }
//  }


  /** Encryption/decryption functions */
  //FUNCTION TO ENCRYPT DATA WHEN WRITTEN INTO STORAGE
  private fun encrypt(strToEncrypt: String) :  String? {
    try
    {
      val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
      }
      //We get the aes key from the keystore if they exists
      val secretKey = keyStore.getKey(ANDROID_AES_ALIAS, null) as SecretKey
      var result = ""
      val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
      cipher.init(Cipher.ENCRYPT_MODE, secretKey)
      val iv = cipher.iv
      val ivString = Base64.encodeToString(iv, Base64.DEFAULT)
      result += Base64.encodeToString(cipher.doFinal(strToEncrypt.toByteArray(Charsets.UTF_8)), Base64.DEFAULT)
      result += IV_SEPARATOR + ivString
      return result
    }
    catch (e: Exception) {
    }
    return null
  }

  //FUNCTION TO DECRYPT DATA WHEN READ FROM STORAGE
  private fun decrypt(strToDecrypt : String) : String? {
    try{
      val split = strToDecrypt.split(IV_SEPARATOR.toRegex())
      val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
      }
      val ivString = split[1]
      val encodedData = split[0]
      //We get the aes key from the keystore if they exists
      val secretKey = keyStore.getKey(ANDROID_AES_ALIAS, null) as SecretKey
      val ivSpec = IvParameterSpec(Base64.decode(ivString, Base64.DEFAULT))
      val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")

      cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
      return  String(cipher.doFinal(Base64.decode(encodedData, Base64.DEFAULT)))
    }catch (e: Exception) {
    }
    return null
  }

  /** Activity functions */
  override fun onAttachedToActivity(binding: ActivityPluginBinding) {
    activity = binding.activity
    binding.addActivityResultListener(this)
  }

  override fun onDetachedFromActivityForConfigChanges() {
    TODO("Not yet implemented")
  }

  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
    TODO("Not yet implemented")
  }

  override fun onDetachedFromActivity() {
    TODO("Not yet implemented")
  }

  //FUNCTION TO CATCH AUTHENTICATION RESULT
  override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
    if (requestCode == REQUEST_CODE_FOR_CREDENTIALS) {
      if (resultCode == Activity.RESULT_OK) {
        val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
          load(null)
        }
        val privateKey: PrivateKey = keyStore.getKey(RSA_KEY_ALIAS, null) as PrivateKey
        val signature: ByteArray? = Signature.getInstance("SHA256withRSA").run {
          initSign(privateKey)
          update(dataToSign.toByteArray())
          sign()
        }
        if (signature != null) {
          signatureResult = Base64.encodeToString(signature, Base64.DEFAULT)
          dataSignature = signatureResult
          val stringConcat = "$signatureResult:$dataToSign"
          pendingResult.success(stringConcat)
        }
        return true
      } else {
        Toast.makeText(context, "Authentication failed.", Toast.LENGTH_SHORT).show()
        pendingResult.success(false)
        activity.finish()
        return false
      }
    }
    else{
      return false
    }
  }

  fun registerWith(registrar: PluginRegistry.Registrar) {
    activity = registrar.activity()
    val channel = MethodChannel(registrar.messenger(), "ed25519_signing_plugin")
    channel.setMethodCallHandler(Ed25519SigningPlugin())
  }

}

//KEYSTORE ALIAS
private const val ANDROID_KEYSTORE = "ff9641b1-c535-4ddf-b98d-8b56ea518340"
//ENCRYPT/DECRYPT KEY ALIAS
private const val ANDROID_AES_ALIAS = "da1500b3-1671-4abd-a12d-358dbd4561a2"
//IV STRING SEPARATOR
private const val IV_SEPARATOR = ";"
//SIGN/VERIFY WITH RSA ALIAS
private const val RSA_KEY_ALIAS = "5297b5c9-84e0-4533-9239-748b2ab8d7ba"
//ALIASES FOR 2 KEYPAIRS OF ED25519 KEYS
private const val ED_PUBLIC_KEY_1_ALIAS = "44aa7c96-36b2-4370-8681-a7fca6e708a1"
private const val ED_PRIVATE_KEY_1_ALIAS = "94451570-af89-4a1c-a716-3659d54d301f"
private const val ED_PUBLIC_KEY_2_ALIAS = "954e0e29-2414-4617-8439-7b8d673023ce"
private const val ED_PRIVATE_KEY_2_ALIAS = "22edeafb-faaa-4130-a218-3be888813efe"
//ALIAS FOR SETTING CHOSEN ALGORITHM
private const val ALGORITHM_ALIAS = "355114e2-35d0-4e55-b764-7cbdf949ce8b"
//REQUEST CODE FOR AUTHENTICATION SCREEN
const val REQUEST_CODE_FOR_CREDENTIALS = 1