import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ed25519_signing_plugin/ed25519_signing_plugin.dart';

void main() {
  const MethodChannel channel = MethodChannel('ed25519_signing_plugin');

  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      return '42';
    });
  });

  tearDown(() {
    channel.setMockMethodCallHandler(null);
  });

  test('getPlatformVersion', () async {
    expect(await Ed25519SigningPlugin.platformVersion, '42');
  });
}
