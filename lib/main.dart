import 'dart:async';
import 'dart:convert';
import 'dart:io' show File;
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart'
    show
        Argon2id,
        Xchacha20,
        AesGcm,
        Cipher,
        SecretKey,
        SecretBox,
        Mac,
        SecretBoxAuthenticationError;
import 'package:file_picker/file_picker.dart' show FilePicker, FilePickerResult;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

// ============================================================
//  الألوان
// ============================================================
const kBg = Color(0xFF080D0B);
const kCard = Color(0xFF101814);
const kCard2 = Color(0xFF16211B);
const kLine = Color(0xFF223229);
const kAccent = Color(0xFF2EE59D);
const kAccentDim = Color(0xFF123D2B);
const kAccentSoft = Color(0x1A2EE59D);
const kAccentLine = Color(0x662EE59D);
const kWarn = Color(0xFFFFB84D);
const kBad = Color(0xFFFF6B6B);
const kBadSoft = Color(0x1AFF6B6B);
const kBadLine = Color(0x66FF6B6B);
const kMuted = Color(0xFF8FA39A);

const EdgeInsets pagePad = EdgeInsets.fromLTRB(16, 8, 16, 28);

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  ErrorWidget.builder = (details) => Directionality(
        textDirection: TextDirection.ltr,
        child: Material(
          color: Colors.black,
          child: SafeArea(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: Text(
                  kReleaseMode
                      ? 'حصل خطأ غير متوقع. اقفل التطبيق وافتحه تاني.'
                      : 'Error:\n${_short(details.exceptionAsString())}',
                  style: const TextStyle(color: Colors.redAccent)),
            ),
          ),
        ),
      );
  runApp(const VaultApp());
}

// ============================================================
//  إعدادات الحماية
// ============================================================
class Level {
  const Level(this.name, this.mem, this.iter);
  final String name;
  final int mem, iter;
}

const levels = [
  Level('عادي', 19456, 2),
  Level('قوي', 65536, 3),
  Level('أقصى', 131072, 3),
  Level('خارق', 131072, 6),
];

const _lvlDesc = [
  'سريع، مناسب للنصوص العادية.',
  'متوازن (موصى بيه): 64MB ذاكرة و3 دورات.',
  'تقيل: 128MB ذاكرة، أصعب بكتير على تخمين كلمة السر.',
  'الأقوى: 128MB و6 دورات. وقته أطول بكتير وممكن يبطّئ الموبايلات الضعيفة.',
];

// أقصى قيم مسموح بيها وقت الفك (حماية من نصوص معدّلة بتحجز ذاكرة ضخمة)
const int kMaxMem = 131072;
const int kMaxIter = 8;

final ValueNotifier<int> wipe = ValueNotifier<int>(0);
final ValueNotifier<int> idleLock = ValueNotifier<int>(0);
final ValueNotifier<int> vaultsChanged = ValueNotifier<int>(0);
final ValueNotifier<int> autoLockMin = ValueNotifier<int>(2);
final ValueNotifier<int> clipSecs = ValueNotifier<int>(30);
final ValueNotifier<bool> appLockOn = ValueNotifier<bool>(false);
final ValueNotifier<bool> appUnlocked = ValueNotifier<bool>(true);
final ValueNotifier<int> graceSecs = ValueNotifier<int>(0);
final ValueNotifier<int> appIdle = ValueNotifier<int>(0);

// بيمنع قايمة النسخ العادية على النصوص الحساسة (النسخ يتم من أزرار التطبيق بس)
Widget noMenu(BuildContext context, EditableTextState state) =>
    const SizedBox.shrink();
bool pickerOpen = false;

const weakMsg =
    'كلمة السر ضعيفة: لازم 14 حرف على الأقل ومتنوعة ومن غير كلمات شائعة. استخدم زر 🎲';
const _commonWords = [
  'password',
  'qwerty',
  '123456',
  '111111',
  '000000',
  'abc123',
  'admin',
  'letmein',
  'welcome',
  'iloveyou',
];

const _walks = [
  'qwert',
  'asdfg',
  'zxcvb',
  'poiuy',
  'lkjhg',
  'qazwsx',
  '1qaz2wsx',
];
final RegExp _sameRun = RegExp(r'(.)\1{3,}');
final RegExp _blockRepeat = RegExp(r'(.{3,6})\1');

// تسلسل زي abcd أو 4321 (4 حروف متتالية أو أكتر)
bool _hasRun(String s) {
  var up = 1, down = 1;
  for (var i = 1; i < s.length; i++) {
    final d = s.codeUnitAt(i) - s.codeUnitAt(i - 1);
    up = d == 1 ? up + 1 : 1;
    down = d == -1 ? down + 1 : 1;
    if (up >= 4 || down >= 4) return true;
  }
  return false;
}

bool isWeak(String p) {
  if (p.length < 14) return true;
  final l = p.toLowerCase();
  if (_commonWords.any((w) => l.contains(w))) return true;
  if (_walks.any((w) => l.contains(w))) return true;
  if (p.split('').toSet().length < 6) return true;
  if (_hasRun(l)) return true;
  if (_sameRun.hasMatch(l) || _blockRepeat.hasMatch(l)) return true;
  return entropyBits(p) < 60;
}

const lockWeakMsg =
    'كلمة القفل ضعيفة: لازم 6 حروف أو أرقام على الأقل، من غير تكرار أو تسلسل (زي 123456).';

// قواعد أخف من كلمات سر التشفير، لأن القفل بيتحمي بتأخير المحاولات الغلط
bool isWeakLock(String p) {
  if (p.length < 6) return true;
  final l = p.toLowerCase();
  if (_commonWords.any((w) => l.contains(w))) return true;
  if (p.split('').toSet().length < 3) return true;
  if (_hasRun(l) || _sameRun.hasMatch(l)) return true;
  return false;
}

String _short(String s) => s.length > 300 ? s.substring(0, 300) : s;

// ============================================================
//  التشفير
//  algo 1 = XChaCha20-Poly1305
//  algo 2 = AES-256-GCM
//  algo 3 = تشفير مزدوج: XChaCha20 ثم AES-256-GCM بمفتاحين مستقلين
// ============================================================
Cipher _cipher(int id) =>
    id == 1 ? Xchacha20.poly1305Aead() : AesGcm.with256bits();

int _nonceLen(int algo) => algo == 1 ? 24 : (algo == 2 ? 12 : 36);
int _keyLen(int algo) => algo == 3 ? 64 : 32;
bool _validAlgo(int a) => a >= 1 && a <= 3;

Uint8List _rand(int n) {
  final r = Random.secure();
  return Uint8List.fromList(List<int>.generate(n, (_) => r.nextInt(256)));
}

Uint8List _u32(int v) => (ByteData(4)..setUint32(0, v)).buffer.asUint8List();

void wipeBytes(List<int> b) {
  try {
    b.fillRange(0, b.length, 0);
  } catch (_) {}
}

Future<List<int>> _derive(Map<String, Object> a) async {
  final kdf = Argon2id(
    memory: a['mem'] as int,
    parallelism: 1,
    iterations: a['iter'] as int,
    hashLength: (a['len'] as int?) ?? 32,
  );
  final key = await kdf.deriveKeyFromPassword(
    password: a['pw'] as String,
    nonce: a['salt'] as List<int>,
  );
  return key.extractBytes();
}

// بيرجّع: ciphertext + mac
Future<Uint8List> _seal(List<int> data, List<int> key, int algo,
    List<int> nonce, List<int> header) async {
  if (algo == 3) {
    final inner = await Xchacha20.poly1305Aead().encrypt(
      data,
      secretKey: SecretKey(key.sublist(0, 32)),
      nonce: nonce.sublist(0, 24),
      aad: header,
    );
    final mid = BytesBuilder()
      ..add(inner.cipherText)
      ..add(inner.mac.bytes);
    final outer = await AesGcm.with256bits().encrypt(
      mid.toBytes(),
      secretKey: SecretKey(key.sublist(32, 64)),
      nonce: nonce.sublist(24, 36),
      aad: header,
    );
    return (BytesBuilder()
          ..add(outer.cipherText)
          ..add(outer.mac.bytes))
        .toBytes();
  }
  final box = await _cipher(algo).encrypt(
    data,
    secretKey: SecretKey(key),
    nonce: nonce,
    aad: header,
  );
  return (BytesBuilder()
        ..add(box.cipherText)
        ..add(box.mac.bytes))
      .toBytes();
}

Future<List<int>> _open(List<int> blob, List<int> key, int algo,
    List<int> nonce, List<int> header) async {
  if (blob.length < 16) throw const FormatException('format');
  if (algo == 3) {
    final outerCt = blob.sublist(0, blob.length - 16);
    final outerMac = blob.sublist(blob.length - 16);
    final mid = await AesGcm.with256bits().decrypt(
      SecretBox(outerCt, nonce: nonce.sublist(24, 36), mac: Mac(outerMac)),
      secretKey: SecretKey(key.sublist(32, 64)),
      aad: header,
    );
    if (mid.length < 16) throw const FormatException('format');
    final innerCt = mid.sublist(0, mid.length - 16);
    final innerMac = mid.sublist(mid.length - 16);
    return Xchacha20.poly1305Aead().decrypt(
      SecretBox(innerCt, nonce: nonce.sublist(0, 24), mac: Mac(innerMac)),
      secretKey: SecretKey(key.sublist(0, 32)),
      aad: header,
    );
  }
  return _cipher(algo).decrypt(
    SecretBox(blob.sublist(0, blob.length - 16),
        nonce: nonce, mac: Mac(blob.sublist(blob.length - 16))),
    secretKey: SecretKey(key),
    aad: header,
  );
}

Future<String> encryptText(
    String text, String pw, int algoId, Level lvl) async {
  final salt = _rand(16);
  final nonce = _rand(_nonceLen(algoId));
  final hb = BytesBuilder()
    ..add([0x4B, 0x43, 1, algoId])
    ..add(_u32(lvl.mem))
    ..addByte(lvl.iter)
    ..addByte(1)
    ..add(salt)
    ..add(nonce);
  final header = hb.toBytes();
  final keyBytes = await compute(_derive, <String, Object>{
    'pw': pw,
    'salt': salt,
    'mem': lvl.mem,
    'iter': lvl.iter,
    'len': _keyLen(algoId),
  });
  try {
    final blob = await _seal(utf8.encode(text), keyBytes, algoId, nonce, header);
    final out = BytesBuilder()
      ..add(header)
      ..add(blob);
    return 'KC1.${base64Url.encode(out.toBytes())}';
  } finally {
    wipeBytes(keyBytes);
  }
}

Future<String> decryptText(String input, String pw) async {
  final s = input.replaceAll(RegExp(r'\s'), '');
  if (!s.startsWith('KC1.')) throw const FormatException('format');
  final b = base64Url.decode(base64Url.normalize(s.substring(4)));
  if (b.length < 26 + 12 + 16 || b[0] != 0x4B || b[1] != 0x43 || b[2] != 1) {
    throw const FormatException('format');
  }
  final algoId = b[3];
  if (!_validAlgo(algoId)) throw const FormatException('algo');
  final mem = ByteData.sublistView(b, 4, 8).getUint32(0);
  final iter = b[8];
  if (mem < 8192 || mem > kMaxMem || iter < 1 || iter > kMaxIter || b[9] != 1) {
    throw const FormatException('params');
  }
  final hLen = 26 + _nonceLen(algoId);
  if (b.length < hLen + 16) throw const FormatException('format');
  final header = b.sublist(0, hLen);
  final salt = b.sublist(10, 26);
  final nonce = b.sublist(26, hLen);
  final blob = b.sublist(hLen);
  final keyBytes = await compute(_derive, <String, Object>{
    'pw': pw,
    'salt': salt,
    'mem': mem,
    'iter': iter,
    'len': _keyLen(algoId),
  });
  try {
    final clear = await _open(blob, keyBytes, algoId, nonce, header);
    return utf8.decode(clear);
  } finally {
    wipeBytes(keyBytes);
  }
}

// ---------- تشفير الملفات (صيغة KF) ----------
// الهيدر: [0x4B,0x46,1,algo] + mem(4) + iter(1) + 1 + salt(16) + nonce
// الباقي: ciphertext + mac(16)
// المحتوى قبل التشفير: nameLen(4) + اسم الملف + بيانات الملف

bool _isKcf(Uint8List b) =>
    b.length >= 26 + 12 + 16 &&
    b[0] == 0x4B &&
    b[1] == 0x46 &&
    b[2] == 1 &&
    _validAlgo(b[3]);

Future<Uint8List> _encBytesJob(Map<String, Object> a) async {
  final data = a['data'] as Uint8List;
  final pw = a['pw'] as String;
  final algoId = a['algo'] as int;
  final mem = a['mem'] as int;
  final iter = a['iter'] as int;
  final salt = _rand(16);
  final nonce = _rand(_nonceLen(algoId));
  final header = (BytesBuilder()
        ..add([0x4B, 0x46, 1, algoId])
        ..add(_u32(mem))
        ..addByte(iter)
        ..addByte(1)
        ..add(salt)
        ..add(nonce))
      .toBytes();
  final keyBytes = await _derive(<String, Object>{
    'pw': pw,
    'salt': salt,
    'mem': mem,
    'iter': iter,
    'len': _keyLen(algoId),
  });
  try {
    final blob = await _seal(data, keyBytes, algoId, nonce, header);
    return (BytesBuilder()
          ..add(header)
          ..add(blob))
        .toBytes();
  } finally {
    wipeBytes(keyBytes);
  }
}

// بيرجع null لو كلمة السر غلط أو الملف اتعدّل أو الصيغة مش سليمة
Future<Uint8List?> _decBytesJob(Map<String, Object> a) async {
  try {
    final b = a['data'] as Uint8List;
    final pw = a['pw'] as String;
    if (!_isKcf(b)) return null;
    final algoId = b[3];
    final mem = ByteData.sublistView(b, 4, 8).getUint32(0);
    final iter = b[8];
    if (mem < 8192 ||
        mem > kMaxMem ||
        iter < 1 ||
        iter > kMaxIter ||
        b[9] != 1) {
      return null;
    }
    final hLen = 26 + _nonceLen(algoId);
    if (b.length < hLen + 16) return null;
    final header = b.sublist(0, hLen);
    final salt = b.sublist(10, 26);
    final nonce = b.sublist(26, hLen);
    final blob = b.sublist(hLen);
    final keyBytes = await _derive(<String, Object>{
      'pw': pw,
      'salt': salt,
      'mem': mem,
      'iter': iter,
      'len': _keyLen(algoId),
    });
    try {
      final clear = await _open(blob, keyBytes, algoId, nonce, header);
      return Uint8List.fromList(clear);
    } finally {
      wipeBytes(keyBytes);
    }
  } catch (_) {
    return null;
  }
}

// ============================================================
//  أدوات مساعدة
// ============================================================
double entropyBits(String p) {
  var pool = 0;
  if (p.contains(RegExp(r'[a-z]'))) pool += 26;
  if (p.contains(RegExp(r'[A-Z]'))) pool += 26;
  if (p.contains(RegExp(r'[0-9]'))) pool += 10;
  if (p.contains(RegExp(r'[^a-zA-Z0-9]'))) pool += 33;
  return pool == 0 ? 0 : p.length * (log(pool) / ln2);
}

String strengthLabel(double bits) => bits < 40
    ? 'ضعيفة'
    : bits < 60
        ? 'متوسطة'
        : bits < 80
            ? 'قوية'
            : 'ممتازة';

Color strengthColor(double bits) => bits < 40
    ? kBad
    : bits < 60
        ? kWarn
        : kAccent;

String genPassword([int n = 24]) {
  const a =
      'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#\$%^&*-_=+?';
  final r = Random.secure();
  return List<String>.generate(n, (_) => a[r.nextInt(a.length)]).join();
}

// مولّد متقدم: بيضمن وجود حرف واحد على الأقل من كل نوع مختار
String genPasswordWith(int n,
    {bool lower = true,
    bool upper = true,
    bool digits = true,
    bool symbols = true,
    bool noAmbiguous = true}) {
  var lo = 'abcdefghijklmnopqrstuvwxyz';
  var up = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  var di = '0123456789';
  const sy = '!@#\$%^&*-_=+?';
  if (noAmbiguous) {
    lo = lo.replaceAll('l', '');
    up = up.replaceAll('I', '').replaceAll('O', '');
    di = di.replaceAll('0', '').replaceAll('1', '');
  }
  final sets = <String>[
    if (lower) lo,
    if (upper) up,
    if (digits) di,
    if (symbols) sy,
  ];
  if (sets.isEmpty) return '';
  final all = sets.join();
  final r = Random.secure();
  String one() =>
      List<String>.generate(n, (_) => all[r.nextInt(all.length)]).join();
  for (var t = 0; t < 50; t++) {
    final s = one();
    final ok = sets.every((cs) => s.split('').any((ch) => cs.contains(ch)));
    if (ok) return s;
  }
  return one();
}

class SecureWindow {
  static const _ch = MethodChannel('vault/secure');

  static Future<void> set(bool on) async {
    try {
      await _ch.invokeMethod('setSecure', {'on': on});
    } catch (_) {}
  }

  static Future<bool> copy(String text, int secs) async {
    try {
      await _ch.invokeMethod('copy', {'text': text, 'secs': secs});
      return true;
    } catch (_) {
      return false;
    }
  }

  static Future<void> clearIf(String text) async {
    try {
      await _ch.invokeMethod('clearIf', {'text': text});
    } catch (_) {}
  }
}

Timer? _clipTimer;

Future<void> copySecure(BuildContext c, String text) async {
  final secs = clipSecs.value;
  final ok = await SecureWindow.copy(text, secs);
  if (!ok) await Clipboard.setData(ClipboardData(text: text));
  HapticFeedback.lightImpact();
  if (c.mounted) {
    ScaffoldMessenger.of(c).showSnackBar(SnackBar(
        content: Text('اتنسخ، وهيتمسح من الحافظة بعد $secs ثانية')));
  }
  _clipTimer?.cancel();
  _clipTimer = Timer(Duration(seconds: secs), () async {
    if (ok) {
      await SecureWindow.clearIf(text);
    } else {
      final d = await Clipboard.getData(Clipboard.kTextPlain);
      if (d?.text == text) {
        await Clipboard.setData(const ClipboardData(text: ''));
      }
    }
  });
}

// ============================================================
//  عناصر الواجهة المشتركة
// ============================================================
InputDecoration inputDeco(String label, {IconData? icon, Widget? suffix}) {
  OutlineInputBorder b(Color c, double w) => OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: BorderSide(color: c, width: w),
      );
  return InputDecoration(
    labelText: label,
    prefixIcon: icon == null ? null : Icon(icon, size: 20),
    suffixIcon: suffix,
    filled: true,
    fillColor: kCard2,
    border: b(kLine, 1),
    enabledBorder: b(kLine, 1),
    focusedBorder: b(kAccent, 1.4),
  );
}

final ButtonStyle kBtn = FilledButton.styleFrom(
  minimumSize: const Size.fromHeight(52),
  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
  textStyle: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700),
);

class Panel extends StatelessWidget {
  const Panel({super.key, required this.child});
  final Widget child;
  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: kCard,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: kLine),
      ),
      child: child,
    );
  }
}

class TabHeader extends StatelessWidget {
  const TabHeader(
      {super.key,
      required this.icon,
      required this.title,
      required this.subtitle});
  final IconData icon;
  final String title, subtitle;
  @override
  Widget build(BuildContext context) {
    return Row(children: [
      Container(
        width: 48,
        height: 48,
        decoration: BoxDecoration(
          color: kAccentDim,
          borderRadius: BorderRadius.circular(14),
        ),
        child: Icon(icon, color: kAccent),
      ),
      const SizedBox(width: 12),
      Expanded(
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(title,
              style:
                  const TextStyle(fontSize: 19, fontWeight: FontWeight.w800)),
          const SizedBox(height: 2),
          Text(subtitle,
              style: const TextStyle(fontSize: 12.5, color: kMuted)),
        ]),
      ),
    ]);
  }
}

class SectionLabel extends StatelessWidget {
  const SectionLabel(this.text, {super.key});
  final String text;
  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Text(text,
          style: const TextStyle(
              fontSize: 13, color: kMuted, fontWeight: FontWeight.w600)),
    );
  }
}

class Msg extends StatelessWidget {
  const Msg(this.text, {super.key, this.good = false});
  final String text;
  final bool good;
  @override
  Widget build(BuildContext context) {
    final c = good ? kAccent : kBad;
    return Container(
      margin: const EdgeInsets.only(top: 12),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: good ? kAccentSoft : kBadSoft,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: good ? kAccentLine : kBadLine),
      ),
      child: Row(children: [
        Icon(good ? Icons.check_circle : Icons.error_outline, color: c, size: 20),
        const SizedBox(width: 10),
        Expanded(
            child: Text(text, style: TextStyle(color: c, fontSize: 13.5))),
      ]),
    );
  }
}

class StrengthMeter extends StatelessWidget {
  const StrengthMeter(this.bits, {super.key});
  final double bits;
  @override
  Widget build(BuildContext context) {
    final c = strengthColor(bits);
    final v = (bits / 100).clamp(0.0, 1.0).toDouble();
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      ClipRRect(
        borderRadius: BorderRadius.circular(6),
        child: TweenAnimationBuilder<double>(
          tween: Tween<double>(begin: 0.0, end: v),
          duration: const Duration(milliseconds: 250),
          builder: (context, value, _) => LinearProgressIndicator(
            value: value,
            minHeight: 7,
            backgroundColor: kLine,
            valueColor: AlwaysStoppedAnimation<Color>(c),
          ),
        ),
      ),
      const SizedBox(height: 6),
      Text('قوة كلمة السر: ${strengthLabel(bits)} · ${bits.round()} بت',
          style: TextStyle(fontSize: 12, color: c)),
    ]);
  }
}

class AlgoPicker extends StatelessWidget {
  const AlgoPicker({super.key, required this.algo, required this.onChanged});
  final int algo;
  final ValueChanged<int> onChanged;
  static const _desc = {
    1: 'XChaCha20-Poly1305: سريع وآمن جدًا ومعمول لنونس عشوائي طويل.',
    2: 'AES-256-GCM: المعيار العالمي، ومدعوم بالعتاد في أغلب المعالجات.',
    3: 'مزدوج: XChaCha20 ثم AES-256-GCM بمفتاحين مستقلين. لو طبقة اتكسرت، التانية تفضل حامية البيانات.',
  };
  @override
  Widget build(BuildContext context) {
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      SizedBox(
        width: double.infinity,
        child: SegmentedButton<int>(
          showSelectedIcon: false,
          segments: const [
            ButtonSegment(value: 1, label: Text('XChaCha20')),
            ButtonSegment(value: 2, label: Text('AES-256')),
            ButtonSegment(value: 3, label: Text('مزدوج')),
          ],
          selected: {algo},
          onSelectionChanged: (v) => onChanged(v.first),
        ),
      ),
      const SizedBox(height: 6),
      Text(_desc[algo] ?? '',
          style: const TextStyle(fontSize: 12, color: kMuted)),
    ]);
  }
}

class LevelPicker extends StatelessWidget {
  const LevelPicker({super.key, required this.lvl, required this.onChanged});
  final int lvl;
  final ValueChanged<int> onChanged;
  @override
  Widget build(BuildContext context) {
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      SizedBox(
        width: double.infinity,
        child: SegmentedButton<int>(
          showSelectedIcon: false,
          segments: [
            for (var i = 0; i < levels.length; i++)
              ButtonSegment(value: i, label: Text(levels[i].name)),
          ],
          selected: {lvl},
          onSelectionChanged: (v) => onChanged(v.first),
        ),
      ),
      const SizedBox(height: 6),
      Text(_lvlDesc[lvl],
          style: TextStyle(fontSize: 12, color: lvl >= 2 ? kWarn : kMuted)),
    ]);
  }
}

class PwField extends StatefulWidget {
  const PwField(this.ctl,
      {super.key,
      this.generate = false,
      this.onChanged,
      this.label = 'كلمة السر'});
  final TextEditingController ctl;
  final String label;
  final bool generate;
  final VoidCallback? onChanged;
  @override
  State<PwField> createState() => _PwFieldState();
}

class _PwFieldState extends State<PwField> {
  bool show = false;
  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: widget.ctl,
      obscureText: !show,
      autocorrect: false,
      enableSuggestions: false,
      enableIMEPersonalizedLearning: false,
      keyboardType: TextInputType.visiblePassword,
      textDirection: TextDirection.ltr,
      onChanged: (_) => widget.onChanged?.call(),
      decoration: inputDeco(
        widget.label,
        icon: Icons.key,
        suffix: Row(mainAxisSize: MainAxisSize.min, children: [
          if (widget.generate)
            IconButton(
              icon: const Icon(Icons.casino),
              tooltip: 'توليد كلمة سر قوية',
              onPressed: () {
                widget.ctl.text = genPassword();
                setState(() => show = true);
                widget.onChanged?.call();
              },
            ),
          IconButton(
            icon: Icon(show ? Icons.visibility_off : Icons.visibility),
            onPressed: () => setState(() => show = !show),
          ),
        ]),
      ),
    );
  }
}

class OutBox extends StatelessWidget {
  const OutBox(this.text, {super.key, this.mono = true});
  final String text;
  final bool mono;
  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(top: 14),
      child: Panel(
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const Row(children: [
            Icon(Icons.verified, color: kAccent, size: 18),
            SizedBox(width: 8),
            Text('النتيجة',
                style:
                    TextStyle(color: kAccent, fontWeight: FontWeight.w700)),
          ]),
          const SizedBox(height: 10),
          SelectableText(
            text,
            contextMenuBuilder: noMenu,
            textDirection: mono ? TextDirection.ltr : null,
            style: TextStyle(
              fontSize: mono ? 13.5 : 15,
              fontFamily: mono ? 'monospace' : null,
              height: 1.45,
            ),
          ),
          const SizedBox(height: 6),
          Align(
            alignment: AlignmentDirectional.centerEnd,
            child: TextButton.icon(
              onPressed: () => copySecure(context, text),
              icon: const Icon(Icons.copy, size: 18),
              label: const Text('نسخ'),
            ),
          ),
        ]),
      ),
    );
  }
}

// ============================================================
//  التطبيق
// ============================================================
class VaultApp extends StatelessWidget {
  const VaultApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'THE CRYPT',
      themeMode: ThemeMode.dark,
      darkTheme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: kBg,
        colorScheme: ColorScheme.fromSeed(
            seedColor: kAccent, brightness: Brightness.dark),
      ),
      builder: (c, child) => Directionality(
          textDirection: TextDirection.rtl,
          child: child ?? const SizedBox.shrink()),
      home: const AppLockGate(child: VaultHome()),
    );
  }
}

class VaultHome extends StatefulWidget {
  const VaultHome({super.key});
  @override
  State<VaultHome> createState() => _VaultHomeState();
}

class _VaultHomeState extends State<VaultHome> with WidgetsBindingObserver {
  bool secure = true;
  int tab = 0;
  Timer? _idle;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    autoLockMin.addListener(_touch);
    _loadSecure();
    _touch();
  }

  // قفل الخزنة تلقائيًا بعد المدة المحددة من غير أي لمس
  void _touch() {
    _idle?.cancel();
    _idle = Timer(Duration(minutes: autoLockMin.value), () {
      idleLock.value++;
      appIdle.value++;
    });
  }

  Future<void> _loadSecure() async {
    try {
      final p = await SharedPreferences.getInstance();
      final al = p.getInt('autolock') ?? 2;
      final cs = p.getInt('clip') ?? 30;
      autoLockMin.value = const [1, 2, 5, 10].contains(al) ? al : 2;
      clipSecs.value = const [15, 30, 60].contains(cs) ? cs : 30;
      final v = p.getBool('secure') ?? true;
      if (mounted) setState(() => secure = v);
      SecureWindow.set(v);
    } catch (_) {}
  }

  Future<void> _toggleSecure() async {
    final next = !secure;
    setState(() => secure = next);
    SecureWindow.set(next);
    try {
      final p = await SharedPreferences.getInstance();
      await p.setBool('secure', next);
    } catch (_) {}
  }

  @override
  void dispose() {
    _idle?.cancel();
    autoLockMin.removeListener(_touch);
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused && !pickerOpen) wipe.value++;
  }

  Widget _tip(IconData icon, String text) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Icon(icon, size: 20, color: kAccent),
        const SizedBox(width: 12),
        Expanded(child: Text(text, style: const TextStyle(height: 1.45))),
      ]),
    );
  }

  void _about() {
    showModalBottomSheet<void>(
      context: context,
      backgroundColor: kCard,
      showDragHandle: true,
      isScrollControlled: true,
      builder: (ctx) => SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(20, 0, 20, 24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('نصايح الأمان',
                  style: TextStyle(fontSize: 19, fontWeight: FontWeight.w800)),
              const SizedBox(height: 10),
              _tip(Icons.key,
                  'قوة الحماية كلها في كلمة السر. استخدم زر 🎲 أو عبارة طويلة عشوائية.'),
              _tip(Icons.layers,
                  'الخيار «مزدوج» بيحط طبقتين تشفير بمفتاحين مستقلين.'),
              _tip(Icons.speed,
                  'رفع مستوى الحماية بيخلي تخمين كلمة السر أغلى بكتير على أي مخترق، مقابل وقت أطول عندك.'),
              _tip(Icons.phonelink_lock,
                  'لو الموبايل فيه فيروس أو كيلوجر أو متعمله روت، مفيش تشفير هيحميك. حدّث النظام وماتنزّلش تطبيقات مجهولة.'),
              _tip(Icons.restore,
                  'مفيش أي طريقة لاسترجاع كلمة السر. لو ضاعت، البيانات ضاعت.'),
              _tip(Icons.wifi_off,
                  'كود التطبيق مفيهوش أي اتصال بالإنترنت، ومفيش حاجة بتتبعت لأي مكان.'),
              _tip(Icons.timer,
                  'الخزنة بتتقفل لوحدها بعد المدة اللي تحددها في تاب «أدوات» (الافتراضي دقيقتين)، أو لما تخرج من التطبيق.'),
            ],
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Listener(
      behavior: HitTestBehavior.translucent,
      onPointerDown: (_) => _touch(),
      child: Scaffold(
        appBar: AppBar(
          backgroundColor: kBg,
          surfaceTintColor: Colors.transparent,
          elevation: 0,
          centerTitle: true,
          title: const Text('THE CRYPT',
              style: TextStyle(letterSpacing: 4, fontWeight: FontWeight.w800)),
          actions: [
            IconButton(
              icon: const Icon(Icons.info_outline),
              tooltip: 'نصايح الأمان',
              onPressed: _about,
            ),
            IconButton(
              icon: Icon(secure ? Icons.shield : Icons.shield_outlined),
              tooltip:
                  secure ? 'منع لقطات الشاشة: شغّال' : 'منع لقطات الشاشة: موقوف',
              onPressed: _toggleSecure,
            ),
          ],
        ),
        body: IndexedStack(
          index: tab,
          children: const [
            EncryptTab(),
            DecryptTab(),
            FilesTab(),
            VaultTab(),
            ToolsTab(),
          ],
        ),
        bottomNavigationBar: NavigationBar(
          selectedIndex: tab,
          backgroundColor: kCard,
          indicatorColor: kAccentDim,
          onDestinationSelected: (i) {
            HapticFeedback.selectionClick();
            if (tab == 3 && i != 3) idleLock.value++;
            setState(() => tab = i);
          },
          destinations: const [
            NavigationDestination(
                icon: Icon(Icons.lock_outline),
                selectedIcon: Icon(Icons.lock),
                label: 'تشفير'),
            NavigationDestination(
                icon: Icon(Icons.lock_open_outlined),
                selectedIcon: Icon(Icons.lock_open),
                label: 'فك'),
            NavigationDestination(
                icon: Icon(Icons.folder_zip_outlined),
                selectedIcon: Icon(Icons.folder_zip),
                label: 'الملفات'),
            NavigationDestination(
                icon: Icon(Icons.inventory_2_outlined),
                selectedIcon: Icon(Icons.inventory_2),
                label: 'خزنتي'),
            NavigationDestination(
                icon: Icon(Icons.tune_outlined),
                selectedIcon: Icon(Icons.tune),
                label: 'أدوات'),
          ],
        ),
      ),
    );
  }
}

// ============================================================
//  تاب تشفير النص
// ============================================================
class EncryptTab extends StatefulWidget {
  const EncryptTab({super.key});
  @override
  State<EncryptTab> createState() => _EncryptTabState();
}

class _EncryptTabState extends State<EncryptTab> {
  final text = TextEditingController();
  final pw = TextEditingController();
  int algo = 3, lvl = 1;
  String? out, err;
  bool busy = false;

  @override
  void initState() {
    super.initState();
    wipe.addListener(_clear);
  }

  @override
  void dispose() {
    wipe.removeListener(_clear);
    text.dispose();
    pw.dispose();
    super.dispose();
  }

  void _clear() {
    text.clear();
    pw.clear();
    if (mounted) setState(() => out = null);
  }

  Future<void> _go() async {
    if (busy) return;
    if (text.text.isEmpty) {
      setState(() => err = 'اكتب النص الأول');
      return;
    }
    if (isWeak(pw.text)) {
      setState(() => err = weakMsg);
      return;
    }
    setState(() {
      busy = true;
      err = null;
      out = null;
    });
    try {
      final r = await encryptText(text.text, pw.text, algo, levels[lvl]);
      if (mounted) setState(() => out = r);
    } catch (_) {
      if (mounted) setState(() => err = 'حصل خطأ أثناء التشفير');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final bits = entropyBits(pw.text);
    return ListView(padding: pagePad, children: [
      const TabHeader(
        icon: Icons.lock,
        title: 'تشفير نص',
        subtitle: 'Argon2id + تشفير مُصادَق، بمفتاح ونونس جديدين لكل رسالة',
      ),
      const SizedBox(height: 16),
      TextField(
        controller: text,
        maxLines: 6,
        autocorrect: false,
        enableSuggestions: false,
        enableIMEPersonalizedLearning: false,
        decoration: inputDeco('النص المراد تشفيره'),
      ),
      const SizedBox(height: 12),
      PwField(pw, generate: true, onChanged: () => setState(() {})),
      const SizedBox(height: 8),
      StrengthMeter(bits),
      const SizedBox(height: 16),
      Panel(
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const SectionLabel('الخوارزمية'),
          AlgoPicker(algo: algo, onChanged: (v) => setState(() => algo = v)),
          const SizedBox(height: 16),
          const SectionLabel('مستوى الحماية'),
          LevelPicker(lvl: lvl, onChanged: (v) => setState(() => lvl = v)),
        ]),
      ),
      const SizedBox(height: 16),
      FilledButton.icon(
        style: kBtn,
        onPressed: busy ? null : _go,
        icon: busy
            ? const SizedBox(
                width: 18,
                height: 18,
                child: CircularProgressIndicator(strokeWidth: 2))
            : const Icon(Icons.lock),
        label: Text(busy ? 'جارٍ التشفير...' : 'تشفير'),
      ),
      if (err != null) Msg(err!),
      if (out != null) OutBox(out!),
    ]);
  }
}

// ============================================================
//  تاب فك تشفير النص
// ============================================================
class DecryptTab extends StatefulWidget {
  const DecryptTab({super.key});
  @override
  State<DecryptTab> createState() => _DecryptTabState();
}

class _DecryptTabState extends State<DecryptTab> {
  final input = TextEditingController();
  final pw = TextEditingController();
  String? out, err;
  bool busy = false;

  @override
  void initState() {
    super.initState();
    wipe.addListener(_clear);
  }

  @override
  void dispose() {
    wipe.removeListener(_clear);
    input.dispose();
    pw.dispose();
    super.dispose();
  }

  void _clear() {
    input.clear();
    pw.clear();
    if (mounted) setState(() => out = null);
  }

  Future<void> _go() async {
    if (busy) return;
    if (input.text.trim().isEmpty || pw.text.isEmpty) {
      setState(() => err = 'ادخل النص المشفّر وكلمة السر');
      return;
    }
    setState(() {
      busy = true;
      err = null;
      out = null;
    });
    try {
      final r = await decryptText(input.text, pw.text);
      if (mounted) setState(() => out = r);
    } on FormatException {
      if (mounted) setState(() => err = 'الصيغة مش صحيحة أو النص ناقص');
    } on SecretBoxAuthenticationError {
      if (mounted) setState(() => err = 'كلمة السر غلط أو النص اتعدّل');
    } catch (_) {
      if (mounted) setState(() => err = 'كلمة السر غلط أو النص اتعدّل');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListView(padding: pagePad, children: [
      const TabHeader(
        icon: Icons.lock_open,
        title: 'فك تشفير نص',
        subtitle: 'الصيغة بتتعرف عليها تلقائيًا، وأي تعديل في النص بيفشّل الفك',
      ),
      const SizedBox(height: 16),
      TextField(
        controller: input,
        maxLines: 6,
        autocorrect: false,
        enableSuggestions: false,
        enableIMEPersonalizedLearning: false,
        textDirection: TextDirection.ltr,
        decoration: inputDeco(
          'النص المشفّر (يبدأ بـ KC1.)',
          suffix: IconButton(
            icon: const Icon(Icons.paste),
            tooltip: 'لصق',
            onPressed: () async {
              final d = await Clipboard.getData(Clipboard.kTextPlain);
              if (d?.text != null) setState(() => input.text = d!.text!);
            },
          ),
        ),
      ),
      const SizedBox(height: 12),
      PwField(pw),
      const SizedBox(height: 16),
      FilledButton.icon(
        style: kBtn,
        onPressed: busy ? null : _go,
        icon: busy
            ? const SizedBox(
                width: 18,
                height: 18,
                child: CircularProgressIndicator(strokeWidth: 2))
            : const Icon(Icons.lock_open),
        label: Text(busy ? 'جارٍ فك التشفير...' : 'فك التشفير'),
      ),
      if (err != null) Msg(err!),
      if (out != null) OutBox(out!, mono: false),
    ]);
  }
}

// ============================================================
//  تاب الملفات
// ============================================================
class FilesTab extends StatefulWidget {
  const FilesTab({super.key});
  @override
  State<FilesTab> createState() => _FilesTabState();
}

class _FilesTabState extends State<FilesTab> {
  static const int maxBytes = 20 * 1024 * 1024;
  final pw = TextEditingController();
  bool enc = true;
  int algo = 3, lvl = 1;
  String? path, fname, err, ok;
  int? size;
  bool busy = false;

  @override
  void initState() {
    super.initState();
    wipe.addListener(_clear);
  }

  @override
  void dispose() {
    wipe.removeListener(_clear);
    pw.dispose();
    super.dispose();
  }

  void _clear() {
    pw.clear();
    if (!mounted) return;
    setState(() {
      path = null;
      fname = null;
      size = null;
      err = null;
      ok = null;
    });
  }

  String _fmtSize(int b) {
    if (b < 1024) return '$b B';
    if (b < 1024 * 1024) return '${(b / 1024).toStringAsFixed(1)} KB';
    return '${(b / (1024 * 1024)).toStringAsFixed(1)} MB';
  }

  Future<void> _pick() async {
    pickerOpen = true;
    try {
      final FilePickerResult? r =
          await FilePicker.platform.pickFiles(withData: false);
      if (!mounted) return;
      if (r == null || r.files.isEmpty) return;
      final f = r.files.single;
      if (f.path == null) {
        setState(() => err = 'معرفتش أقرأ الملف ده');
        return;
      }
      setState(() {
        path = f.path;
        fname = f.name;
        size = f.size;
        err = null;
        ok = null;
      });
    } catch (_) {
      if (mounted) setState(() => err = 'حصل خطأ أثناء اختيار الملف');
    } finally {
      pickerOpen = false;
    }
  }

  Future<String?> _save(String name, Uint8List bytes) async {
    pickerOpen = true;
    try {
      return await FilePicker.platform.saveFile(
        dialogTitle: 'اختار مكان الحفظ',
        fileName: name,
        bytes: bytes,
      );
    } finally {
      pickerOpen = false;
    }
  }

  Future<void> _go() async {
    if (busy) return;
    final p = path;
    final n = fname;
    final sz = size ?? 0;
    if (p == null || n == null) {
      setState(() {
        err = 'اختار ملف الأول';
        ok = null;
      });
      return;
    }
    if (pw.text.isEmpty) {
      setState(() {
        err = 'اكتب كلمة السر';
        ok = null;
      });
      return;
    }
    if (enc && isWeak(pw.text)) {
      setState(() {
        err = weakMsg;
        ok = null;
      });
      return;
    }
    if (sz > maxBytes + 4096) {
      setState(() {
        err = 'الملف كبير: الحد الأقصى 20 ميجا';
        ok = null;
      });
      return;
    }
    setState(() {
      busy = true;
      err = null;
      ok = null;
    });
    try {
      final raw = await File(p).readAsBytes();
      if (enc) {
        if (raw.length > maxBytes) {
          if (mounted) setState(() => err = 'الملف كبير: الحد الأقصى 20 ميجا');
          return;
        }
        final nb = utf8.encode(n);
        final plain = (BytesBuilder()
              ..add(_u32(nb.length))
              ..add(nb)
              ..add(raw))
            .toBytes();
        final out = await compute(_encBytesJob, <String, Object>{
          'data': plain,
          'pw': pw.text,
          'algo': algo,
          'mem': levels[lvl].mem,
          'iter': levels[lvl].iter,
        });
        final dest = await _save('$n.kcf', out);
        if (!mounted) return;
        setState(() => ok = dest == null ? 'اتلغى الحفظ' : 'تم التشفير والحفظ');
      } else {
        if (!_isKcf(raw)) {
          if (mounted) {
            setState(() => err = 'الملف ده مش ملف مشفّر من التطبيق');
          }
          return;
        }
        final res = await compute(_decBytesJob, <String, Object>{
          'data': raw,
          'pw': pw.text,
        });
        if (res == null) {
          if (mounted) setState(() => err = 'كلمة السر غلط أو الملف اتعدّل');
          return;
        }
        if (res.length < 4) throw const FormatException('format');
        final nl = ByteData.sublistView(res, 0, 4).getUint32(0);
        if (nl > 255 || 4 + nl > res.length) {
          throw const FormatException('format');
        }
        var name = utf8.decode(res.sublist(4, 4 + nl), allowMalformed: true);
        name = name.replaceAll(RegExp(r'[\\/:*?"<>|\x00-\x1F]'), '_').trim();
        if (name.isEmpty || name == '.' || name == '..') {
          name = 'decrypted_file';
        }
        final data = Uint8List.fromList(res.sublist(4 + nl));
        final dest = await _save(name, data);
        if (!mounted) return;
        setState(
            () => ok = dest == null ? 'اتلغى الحفظ' : 'تم فك التشفير والحفظ');
      }
    } on FormatException {
      if (mounted) setState(() => err = 'صيغة الملف مش صحيحة');
    } catch (_) {
      if (mounted) setState(() => err = 'حصل خطأ أثناء العملية');
    } finally {
      pickerOpen = false;
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final bits = entropyBits(pw.text);
    return ListView(padding: pagePad, children: [
      const TabHeader(
        icon: Icons.folder_zip,
        title: 'تشفير الملفات',
        subtitle: 'شفّر أي ملف (لحد 20 ميجا) واحفظه بامتداد .kcf',
      ),
      const SizedBox(height: 16),
      SizedBox(
        width: double.infinity,
        child: SegmentedButton<bool>(
          showSelectedIcon: false,
          segments: const [
            ButtonSegment(
                value: true,
                label: Text('تشفير ملف'),
                icon: Icon(Icons.lock)),
            ButtonSegment(
                value: false,
                label: Text('فك تشفير ملف'),
                icon: Icon(Icons.lock_open)),
          ],
          selected: {enc},
          onSelectionChanged: busy
              ? null
              : (v) => setState(() {
                    enc = v.first;
                    path = null;
                    fname = null;
                    size = null;
                    err = null;
                    ok = null;
                  }),
        ),
      ),
      const SizedBox(height: 12),
      InkWell(
        borderRadius: BorderRadius.circular(18),
        onTap: busy ? null : _pick,
        child: Panel(
          child: Row(children: [
            Icon(fname == null ? Icons.upload_file : Icons.insert_drive_file,
                color: kAccent),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                fname == null
                    ? (enc
                        ? 'اضغط لاختيار الملف المراد تشفيره'
                        : 'اضغط لاختيار الملف المشفّر (.kcf)')
                    : '${fname!}  ·  ${_fmtSize(size ?? 0)}',
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ]),
        ),
      ),
      const SizedBox(height: 12),
      PwField(pw, generate: enc, onChanged: () => setState(() {})),
      if (enc) ...[
        const SizedBox(height: 8),
        StrengthMeter(bits),
        const SizedBox(height: 16),
        Panel(
          child:
              Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const SectionLabel('الخوارزمية'),
            AlgoPicker(algo: algo, onChanged: (v) => setState(() => algo = v)),
            const SizedBox(height: 16),
            const SectionLabel('مستوى الحماية'),
            LevelPicker(lvl: lvl, onChanged: (v) => setState(() => lvl = v)),
          ]),
        ),
      ],
      const SizedBox(height: 16),
      FilledButton.icon(
        style: kBtn,
        onPressed: busy ? null : _go,
        icon: busy
            ? const SizedBox(
                width: 18,
                height: 18,
                child: CircularProgressIndicator(strokeWidth: 2))
            : Icon(enc ? Icons.lock : Icons.lock_open),
        label: Text(busy
            ? 'جارٍ التنفيذ...'
            : (enc ? 'تشفير وحفظ' : 'فك التشفير وحفظ')),
      ),
      if (err != null) Msg(err!),
      if (ok != null) Msg(ok!, good: true),
      const SizedBox(height: 14),
      const Text(
        'اسم الملف الأصلي بيتخزّن جوه الملف المشفّر نفسه، فمش بيظهر من برّه.',
        style: TextStyle(fontSize: 12, color: kMuted),
      ),
    ]);
  }
}

// ============================================================
//  الخزنة
// ============================================================
class Session {
  Session(this.slot, this.key, this.header, this.items, this.algo);
  final String slot;
  final Uint8List key, header;
  final int algo;
  List<Map<String, dynamic>> items;
  bool closed = false;
}

class VaultStore {
  static const int maxSlots = 5;

  static Future<Uint8List> _key(
          String pw, List<int> salt, int mem, int iter, int len) async =>
      Uint8List.fromList(await compute(_derive, <String, Object>{
        'pw': pw,
        'salt': salt,
        'mem': mem,
        'iter': iter,
        'len': len,
      }));

  static Future<void> _q = Future<void>.value();

  static Future<void> save(Session s) {
    final f = _q.then((_) => _saveNow(s));
    _q = f.catchError((_) {});
    return f;
  }

  // بيقفل الجلسة بعد ما كل الحفظ المعلّق يخلص، وبيمسح المفتاح والبيانات من الذاكرة
  static Future<void> close(Session s) {
    final f = _q.then((_) {
      s.closed = true;
      wipeBytes(s.key);
      for (final m in s.items) {
        m.clear();
      }
      s.items.clear();
    });
    _q = f.catchError((_) {});
    return f;
  }

  static Future<void> delete(String slot) {
    final f = _q.then((_) async {
      final p = await SharedPreferences.getInstance();
      await p.remove(slot);
    });
    _q = f.catchError((_) {});
    return f;
  }

  static Future<void> _saveNow(Session s) async {
    if (s.closed) return;
    final nonce = _rand(_nonceLen(s.algo));
    final blob = await _seal(
        utf8.encode(jsonEncode(s.items)), s.key, s.algo, nonce, s.header);
    final out = BytesBuilder()
      ..add(s.header)
      ..add(nonce)
      ..add(blob);
    final p = await SharedPreferences.getInstance();
    await p.setString(s.slot, base64Url.encode(out.toBytes()));
  }

  static Future<List<String>> slots() async {
    final p = await SharedPreferences.getInstance();
    final l = p.getKeys().where((k) => k.startsWith('vault.')).toList()
      ..sort();
    return l;
  }

  static Future<String?> freeSlot() async {
    final used = await slots();
    for (var i = 1; i <= maxSlots; i++) {
      final name = 'vault.$i';
      if (!used.contains(name)) return name;
    }
    return null;
  }

  static Future<Session> create(String slot, String pw,
      List<Map<String, dynamic>> items, Level lvl) async {
    const algo = 3;
    final salt = _rand(16);
    final header = (BytesBuilder()
          ..add([0x4B, 0x56, 2, algo])
          ..add(_u32(lvl.mem))
          ..addByte(lvl.iter)
          ..addByte(1)
          ..add(salt))
        .toBytes();
    final key = await _key(pw, salt, lvl.mem, lvl.iter, _keyLen(algo));
    final s = Session(slot, key, header, items, algo);
    await save(s);
    return s;
  }

  static Future<Session?> tryOpen(String slot, String pw) async {
    Uint8List? key;
    try {
      final p = await SharedPreferences.getInstance();
      final raw = p.getString(slot);
      if (raw == null) return null;
      final b = base64Url.decode(base64Url.normalize(raw));
      if (b.length < 26 + 12 + 16) return null;
      if (b[0] != 0x4B || b[1] != 0x56 || (b[2] != 1 && b[2] != 2)) return null;
      final algo = b[3];
      if (!_validAlgo(algo)) return null;
      if (b[2] == 1 && algo != 1) return null;
      final nl = _nonceLen(algo);
      if (b.length < 26 + nl + 16) return null;
      final mem = ByteData.sublistView(b, 4, 8).getUint32(0);
      final iter = b[8];
      if (mem < 8192 ||
          mem > kMaxMem ||
          iter < 1 ||
          iter > kMaxIter ||
          b[9] != 1) {
        return null;
      }
      final header = Uint8List.fromList(b.sublist(0, 26));
      final salt = b.sublist(10, 26);
      final nonce = b.sublist(26, 26 + nl);
      final blob = b.sublist(26 + nl);
      key = await _key(pw, salt, mem, iter, _keyLen(algo));
      final clear = await _open(blob, key, algo, nonce, header);
      final list = jsonDecode(utf8.decode(clear)) as List;
      final items = <Map<String, dynamic>>[
        for (final e in list) Map<String, dynamic>.from(e as Map),
      ];
      return Session(slot, key, header, items, algo);
    } catch (_) {
      if (key != null) wipeBytes(key);
      return null;
    }
  }

  // بيجرّب كلمة السر على كل الخزن الموجودة ويفتح اللي تطابقها
  static Future<Session?> openAny(String pw) async {
    final all = await slots();
    for (final slot in all) {
      final s = await tryOpen(slot, pw);
      if (s != null) return s;
    }
    return null;
  }

  // ----- تأخير المحاولات الغلط (حماية من التخمين على نفس الجهاز) -----
  static Future<int> lockedForMs() async {
    final p = await SharedPreferences.getInstance();
    final until = p.getInt('vault_until') ?? 0;
    final left = until - DateTime.now().millisecondsSinceEpoch;
    return left > 0 ? left : 0;
  }

  static Future<void> noteFail() async {
    final p = await SharedPreferences.getInstance();
    final fails = (p.getInt('vault_fails') ?? 0) + 1;
    await p.setInt('vault_fails', fails);
    if (fails >= 3) {
      final secs = min(900, 5 * (1 << min(fails - 3, 8)));
      await p.setInt('vault_until',
          DateTime.now().millisecondsSinceEpoch + secs * 1000);
    }
  }

  static Future<void> noteOk() async {
    final p = await SharedPreferences.getInstance();
    await p.remove('vault_fails');
    await p.remove('vault_until');
  }

  // مسح كل الخزن (بعد ما أي حفظ معلّق يخلص)
  static Future<void> deleteAll() {
    final f = _q.then((_) async {
      final p = await SharedPreferences.getInstance();
      final keys =
          p.getKeys().where((k) => k.startsWith('vault.')).toList();
      for (final k in keys) {
        await p.remove(k);
      }
      await p.remove('vault_fails');
      await p.remove('vault_until');
    });
    _q = f.catchError((_) {});
    return f;
  }

  // النص المشفّر المخزّن للخزنة (هو نفسه محتوى النسخة الاحتياطية)
  static Future<String?> exportRaw(String slot) async {
    await _q;
    final p = await SharedPreferences.getInstance();
    return p.getString(slot);
  }

  // بيتأكد إن الملف شكله خزنة سليمة (من غير كلمة السر) ويخزنها في خانة فاضية
  // النتيجة: ok / bad / dup / full
  static Future<String> importRaw(String raw) async {
    final s = raw.trim();
    try {
      final b = base64Url.decode(base64Url.normalize(s));
      if (b.length < 26 + 12 + 16 ||
          b[0] != 0x4B ||
          b[1] != 0x56 ||
          (b[2] != 1 && b[2] != 2)) {
        return 'bad';
      }
      final algo = b[3];
      if (!_validAlgo(algo) || (b[2] == 1 && algo != 1)) return 'bad';
      final mem = ByteData.sublistView(b, 4, 8).getUint32(0);
      final iter = b[8];
      if (mem < 8192 ||
          mem > kMaxMem ||
          iter < 1 ||
          iter > kMaxIter ||
          b[9] != 1) {
        return 'bad';
      }
    } catch (_) {
      return 'bad';
    }
    await _q;
    final used = await slots();
    final p = await SharedPreferences.getInstance();
    for (final k in used) {
      if (p.getString(k) == s) return 'dup';
    }
    final slot = await freeSlot();
    if (slot == null) return 'full';
    await p.setString(slot, s);
    return 'ok';
  }
}

class ItemDialog extends StatefulWidget {
  const ItemDialog({super.key, this.initial});
  final Map<String, dynamic>? initial;
  @override
  State<ItemDialog> createState() => _ItemDialogState();
}

class _ItemDialogState extends State<ItemDialog> {
  late final TextEditingController t;
  late final TextEditingController u;
  late final TextEditingController p;
  late final TextEditingController n;

  @override
  void initState() {
    super.initState();
    final i = widget.initial;
    t = TextEditingController(text: (i?['t'] ?? '').toString());
    u = TextEditingController(text: (i?['u'] ?? '').toString());
    p = TextEditingController(text: (i?['p'] ?? '').toString());
    n = TextEditingController(text: (i?['n'] ?? '').toString());
  }

  @override
  void dispose() {
    t.dispose();
    u.dispose();
    p.dispose();
    n.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: kCard,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(22)),
      title: Text(widget.initial == null ? 'عنصر جديد' : 'تعديل العنصر'),
      content: SizedBox(
        width: double.maxFinite,
        child: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            const SizedBox(height: 6),
            TextField(
              controller: t,
              autocorrect: false,
              enableSuggestions: false,
              enableIMEPersonalizedLearning: false,
              decoration: inputDeco('العنوان', icon: Icons.title),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: u,
              autocorrect: false,
              enableSuggestions: false,
              enableIMEPersonalizedLearning: false,
              textDirection: TextDirection.ltr,
              decoration:
                  inputDeco('اسم المستخدم / الإيميل', icon: Icons.person),
            ),
            const SizedBox(height: 10),
            PwField(p, generate: true, label: 'كلمة السر / السر'),
            const SizedBox(height: 10),
            TextField(
              controller: n,
              maxLines: 4,
              autocorrect: false,
              enableSuggestions: false,
              enableIMEPersonalizedLearning: false,
              decoration: inputDeco('ملاحظات', icon: Icons.notes),
            ),
          ]),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('إلغاء'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(<String, dynamic>{
            't': t.text.trim(),
            'u': u.text.trim(),
            'p': p.text,
            'n': n.text,
          }),
          child: const Text('حفظ'),
        ),
      ],
    );
  }
}

class ItemTile extends StatefulWidget {
  const ItemTile(
      {super.key,
      required this.item,
      required this.fav,
      required this.onFav,
      required this.onEdit,
      required this.onDelete});
  final Map<String, dynamic> item;
  final bool fav;
  final VoidCallback onFav, onEdit, onDelete;
  @override
  State<ItemTile> createState() => _ItemTileState();
}

class _ItemTileState extends State<ItemTile> {
  bool show = false;

  @override
  Widget build(BuildContext context) {
    final it = widget.item;
    final title = (it['t'] ?? '').toString();
    final user = (it['u'] ?? '').toString();
    final secret = (it['p'] ?? '').toString();
    final note = (it['n'] ?? '').toString();
    final letter =
        title.isEmpty ? '؟' : String.fromCharCode(title.runes.first);
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      clipBehavior: Clip.antiAlias,
      decoration: BoxDecoration(
        color: kCard,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: kLine),
      ),
      child: Theme(
        data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
        child: ExpansionTile(
          shape: const Border(),
          collapsedShape: const Border(),
          leading: CircleAvatar(
            backgroundColor: kAccentDim,
            child: Text(letter,
                style: const TextStyle(
                    color: kAccent, fontWeight: FontWeight.w800)),
          ),
          title: Row(children: [
            Expanded(
              child: Text(title.isEmpty ? '(بدون عنوان)' : title,
                  style: const TextStyle(fontWeight: FontWeight.w700)),
            ),
            if (widget.fav) const Icon(Icons.star, size: 18, color: kWarn),
          ]),
          subtitle: user.isEmpty
              ? null
              : Text(user, style: const TextStyle(color: kMuted, fontSize: 12.5)),
          childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
          expandedCrossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (user.isNotEmpty)
              Row(children: [
                const Icon(Icons.person, size: 18, color: kMuted),
                const SizedBox(width: 8),
                Expanded(
                    child: SelectableText(user, contextMenuBuilder: noMenu)),
                IconButton(
                  icon: const Icon(Icons.copy, size: 20),
                  tooltip: 'نسخ اسم المستخدم',
                  onPressed: () => copySecure(context, user),
                ),
              ]),
            if (secret.isNotEmpty)
              Row(children: [
                const Icon(Icons.key, size: 18, color: kMuted),
                const SizedBox(width: 8),
                Expanded(
                  child: show
                      ? SelectableText(secret,
                          contextMenuBuilder: noMenu,
                          textDirection: TextDirection.ltr,
                          style: const TextStyle(fontFamily: 'monospace'))
                      : const Text('••••••••••••'),
                ),
                IconButton(
                  icon: Icon(show ? Icons.visibility_off : Icons.visibility,
                      size: 20),
                  onPressed: () => setState(() => show = !show),
                ),
                IconButton(
                  icon: const Icon(Icons.copy, size: 20),
                  tooltip: 'نسخ',
                  onPressed: () => copySecure(context, secret),
                ),
              ]),
            if (note.isNotEmpty)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 6),
                child: SelectableText(note,
                    contextMenuBuilder: noMenu,
                    style: const TextStyle(color: kMuted, height: 1.4)),
              ),
            Row(mainAxisAlignment: MainAxisAlignment.end, children: [
              TextButton.icon(
                onPressed: widget.onFav,
                icon: Icon(widget.fav ? Icons.star : Icons.star_border,
                    size: 18),
                label: Text(widget.fav ? 'إلغاء التثبيت' : 'تثبيت'),
              ),
              TextButton.icon(
                onPressed: widget.onEdit,
                icon: const Icon(Icons.edit, size: 18),
                label: const Text('تعديل'),
              ),
              TextButton.icon(
                onPressed: widget.onDelete,
                icon: const Icon(Icons.delete, size: 18),
                label: const Text('حذف'),
              ),
            ]),
          ],
        ),
      ),
    );
  }
}

class VaultTab extends StatefulWidget {
  const VaultTab({super.key});
  @override
  State<VaultTab> createState() => _VaultTabState();
}

class _VaultTabState extends State<VaultTab> {
  final pw = TextEditingController();
  final pw2 = TextEditingController();
  Session? session;
  List<String> slots = const [];
  bool loaded = false;
  bool creating = false;
  bool busy = false;
  int cl = 1;
  String? err;
  int _epoch = 0;
  final search = TextEditingController();
  String q = '';

  @override
  void initState() {
    super.initState();
    wipe.addListener(_lock);
    idleLock.addListener(_lock);
    vaultsChanged.addListener(_refreshSlots);
    _refreshSlots();
  }

  @override
  void dispose() {
    wipe.removeListener(_lock);
    idleLock.removeListener(_lock);
    vaultsChanged.removeListener(_refreshSlots);
    final s = session;
    if (s != null) VaultStore.close(s);
    pw.dispose();
    pw2.dispose();
    search.dispose();
    super.dispose();
  }

  Future<void> _refreshSlots() async {
    try {
      final s = await VaultStore.slots();
      if (!mounted) return;
      setState(() {
        slots = s;
        loaded = true;
      });
    } catch (_) {
      if (mounted) setState(() => loaded = true);
    }
  }

  void _snack(String m) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(m)));
  }

  void _lock() {
    _epoch++;
    final s = session;
    session = null;
    if (s != null) VaultStore.close(s);
    pw.clear();
    pw2.clear();
    search.clear();
    if (!mounted) return;
    if (s != null) Navigator.of(context).popUntil((r) => r.isFirst);
    setState(() {
      err = null;
      creating = false;
      q = '';
    });
  }

  Future<void> _unlock() async {
    if (busy) return;
    if (pw.text.isEmpty) {
      setState(() => err = 'اكتب كلمة السر');
      return;
    }
    final ep = _epoch;
    setState(() {
      busy = true;
      err = null;
    });
    try {
      final wait = await VaultStore.lockedForMs();
      if (wait > 0) {
        if (mounted) {
          setState(() => err =
              'محاولات غلط كتير. استنى ${(wait / 1000).ceil()} ثانية وجرّب تاني');
        }
        return;
      }
      final s = await VaultStore.openAny(pw.text);
      if (!mounted || ep != _epoch) {
        if (s != null) VaultStore.close(s);
        return;
      }
      if (s == null) {
        await VaultStore.noteFail();
        final w = await VaultStore.lockedForMs();
        if (mounted) {
          setState(() => err = w > 0
              ? 'كلمة السر غلط. استنى ${(w / 1000).ceil()} ثانية قبل المحاولة الجاية'
              : 'كلمة السر غلط');
        }
      } else {
        await VaultStore.noteOk();
        pw.clear();
        if (mounted) setState(() => session = s);
      }
    } catch (_) {
      if (mounted) setState(() => err = 'حصل خطأ أثناء فتح الخزنة');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> _create() async {
    if (busy) return;
    if (isWeak(pw.text)) {
      setState(() => err = weakMsg);
      return;
    }
    if (pw.text != pw2.text) {
      setState(() => err = 'كلمتين السر مش متطابقتين');
      return;
    }
    final ep = _epoch;
    setState(() {
      busy = true;
      err = null;
    });
    try {
      final slot = await VaultStore.freeSlot();
      if (slot == null) {
        if (mounted) setState(() => err = 'وصلت للحد الأقصى من الخزن');
        return;
      }
      final existing = await VaultStore.slots();
      if (existing.isNotEmpty) {
        final dup = await VaultStore.openAny(pw.text);
        if (dup != null) {
          VaultStore.close(dup);
          if (mounted) {
            setState(() => err = 'كلمة السر دي مستخدمة في خزنة تانية');
          }
          return;
        }
      }
      final s = await VaultStore.create(
          slot, pw.text, <Map<String, dynamic>>[], levels[cl]);
      if (!mounted || ep != _epoch) {
        VaultStore.close(s);
        return;
      }
      pw.clear();
      pw2.clear();
      setState(() {
        session = s;
        creating = false;
      });
      await _refreshSlots();
    } catch (_) {
      if (mounted) setState(() => err = 'حصل خطأ أثناء إنشاء الخزنة');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> _persist() async {
    final s = session;
    if (s == null) return;
    try {
      await VaultStore.save(s);
    } catch (_) {
      _snack('حصل خطأ أثناء الحفظ');
    }
  }

  Future<bool> _confirm(String msg) async {
    final r = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: kCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(22)),
        content: Text(msg),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('إلغاء'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('تأكيد'),
          ),
        ],
      ),
    );
    return r == true;
  }

  Future<void> _add() async {
    final s = session;
    if (s == null) return;
    final r = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (_) => const ItemDialog(),
    );
    if (!mounted) return;
    final cur = session;
    if (r == null || cur == null || !identical(cur, s)) return;
    setState(() => cur.items.add(r));
    await _persist();
  }

  Future<void> _edit(int i) async {
    final s = session;
    if (s == null || i >= s.items.length) return;
    final r = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (_) => ItemDialog(initial: s.items[i]),
    );
    if (!mounted) return;
    final cur = session;
    if (r == null ||
        cur == null ||
        !identical(cur, s) ||
        i >= cur.items.length) {
      return;
    }
    if (cur.items[i]['f'] == true) r['f'] = true;
    setState(() => cur.items[i] = r);
    await _persist();
  }

  Future<void> _fav(int i) async {
    final s = session;
    if (s == null || i >= s.items.length) return;
    setState(() => s.items[i]['f'] = s.items[i]['f'] != true);
    await _persist();
  }

  Future<void> _delete(int i) async {
    final s = session;
    if (s == null || i >= s.items.length) return;
    final ok = await _confirm('تحذف العنصر ده؟');
    if (!mounted) return;
    final cur = session;
    if (!ok || cur == null || !identical(cur, s) || i >= cur.items.length) {
      return;
    }
    setState(() => cur.items.removeAt(i));
    await _persist();
  }

  Future<void> _deleteVault() async {
    final s = session;
    if (s == null) return;
    final ok = await _confirm(
        'تحذف الخزنة كلها نهائيًا؟ مفيش أي طريقة للرجوع فيها.');
    if (!ok || !mounted) return;
    try {
      await VaultStore.delete(s.slot);
    } catch (_) {
      _snack('حصل خطأ أثناء الحذف');
      return;
    }
    _lock();
    await _refreshSlots();
  }

  Future<void> _export() async {
    final s = session;
    if (s == null) return;
    pickerOpen = true;
    try {
      final raw = await VaultStore.exportRaw(s.slot);
      if (raw == null) {
        _snack('مفيش بيانات للتصدير');
        return;
      }
      final dest = await FilePicker.platform.saveFile(
        dialogTitle: 'احفظ النسخة الاحتياطية',
        fileName: 'vault_backup.kcv',
        bytes: Uint8List.fromList(utf8.encode(raw)),
      );
      _snack(dest == null
          ? 'اتلغى الحفظ'
          : 'تم حفظ النسخة الاحتياطية (مشفّرة بنفس كلمة سر الخزنة)');
    } catch (_) {
      _snack('حصل خطأ أثناء التصدير');
    } finally {
      pickerOpen = false;
    }
  }

  Future<void> _import() async {
    if (busy) return;
    pickerOpen = true;
    try {
      final r = await FilePicker.platform.pickFiles(withData: false);
      if (r == null || r.files.isEmpty) return;
      final path = r.files.single.path;
      if (path == null) {
        _snack('معرفتش أقرأ الملف ده');
        return;
      }
      final f = File(path);
      if (await f.length() > 5 * 1024 * 1024) {
        _snack('الملف ده مش نسخة خزنة (حجمه كبير)');
        return;
      }
      final raw = utf8.decode(await f.readAsBytes(), allowMalformed: true);
      final res = await VaultStore.importRaw(raw);
      if (res == 'ok') {
        _snack('تم الاستيراد. افتح الخزنة بكلمة السر بتاعتها');
        await _refreshSlots();
      } else if (res == 'dup') {
        _snack('الخزنة دي موجودة عندك بالفعل');
      } else if (res == 'full') {
        _snack('وصلت للحد الأقصى من الخزن. احذف واحدة الأول');
      } else {
        _snack('الملف ده مش نسخة احتياطية سليمة');
      }
    } catch (_) {
      _snack('حصل خطأ أثناء الاستيراد');
    } finally {
      pickerOpen = false;
    }
  }

  bool _match(Map<String, dynamic> m, String ql) {
    for (final k in const ['t', 'u', 'n']) {
      if ((m[k] ?? '').toString().toLowerCase().contains(ql)) return true;
    }
    return false;
  }

  Widget _open(Session s) {
    final ql = q.trim().toLowerCase();
    final idx = <int>[
      for (var i = 0; i < s.items.length; i++)
        if (ql.isEmpty || _match(s.items[i], ql)) i,
    ];
    idx.sort((a, b) {
      final fa = s.items[a]['f'] == true ? 0 : 1;
      final fb = s.items[b]['f'] == true ? 0 : 1;
      return fa != fb ? fa - fb : a - b;
    });
    return Column(children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(16, 4, 8, 4),
        child: Row(children: [
          const Icon(Icons.lock_open, color: kAccent),
          const SizedBox(width: 10),
          Expanded(
            child: Text('الخزنة مفتوحة · ${s.items.length} عنصر',
                style:
                    const TextStyle(fontSize: 16, fontWeight: FontWeight.w700)),
          ),
          IconButton(
            icon: const Icon(Icons.add_circle, color: kAccent),
            tooltip: 'إضافة',
            onPressed: _add,
          ),
          IconButton(
            icon: const Icon(Icons.lock),
            tooltip: 'قفل',
            onPressed: _lock,
          ),
          PopupMenuButton<String>(
            onSelected: (v) {
              if (v == 'del') _deleteVault();
              if (v == 'export') _export();
            },
            itemBuilder: (_) => const [
              PopupMenuItem<String>(
                  value: 'export', child: Text('تصدير نسخة احتياطية')),
              PopupMenuItem<String>(value: 'del', child: Text('حذف الخزنة')),
            ],
          ),
        ]),
      ),
      if (s.items.length > 4 || q.isNotEmpty)
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 4, 16, 4),
          child: TextField(
            controller: search,
            autocorrect: false,
            enableSuggestions: false,
            enableIMEPersonalizedLearning: false,
            onChanged: (v) => setState(() => q = v),
            decoration: inputDeco('بحث في الخزنة', icon: Icons.search),
          ),
        ),
      Expanded(
        child: s.items.isEmpty
            ? Center(
                child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: const [
                      Icon(Icons.inventory_2_outlined, size: 56, color: kMuted),
                      SizedBox(height: 10),
                      Text('الخزنة فاضية',
                          style: TextStyle(
                              fontSize: 16, fontWeight: FontWeight.w700)),
                      SizedBox(height: 4),
                      Text('اضغط + عشان تضيف أول عنصر',
                          style: TextStyle(color: kMuted)),
                    ]),
              )
            : (idx.isEmpty
                ? const Center(
                    child: Text('مفيش نتايج للبحث',
                        style: TextStyle(color: kMuted)))
                : ListView.builder(
                    padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
                    itemCount: idx.length,
                    itemBuilder: (c, n) {
                      final i = idx[n];
                      return ItemTile(
                        key: ObjectKey(s.items[i]),
                        item: s.items[i],
                        fav: s.items[i]['f'] == true,
                        onFav: () => _fav(i),
                        onEdit: () => _edit(i),
                        onDelete: () => _delete(i),
                      );
                    },
                  )),
      ),
    ]);
  }

  Widget _locked() {
    final mk = creating || slots.isEmpty;
    final bits = entropyBits(pw.text);
    return ListView(padding: pagePad, children: [
      TabHeader(
        icon: Icons.inventory_2,
        title: mk ? 'إنشاء خزنة جديدة' : 'الخزنة مقفولة',
        subtitle: mk
            ? 'اختار كلمة سر قوية. مفيش أي طريقة لاسترجاعها'
            : 'اكتب كلمة السر لفتح الخزنة',
      ),
      const SizedBox(height: 16),
      PwField(pw, generate: mk, onChanged: () => setState(() {})),
      if (mk) ...[
        const SizedBox(height: 8),
        StrengthMeter(bits),
        const SizedBox(height: 12),
        PwField(pw2, label: 'تأكيد كلمة السر'),
        const SizedBox(height: 16),
        Panel(
          child:
              Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const SectionLabel('مستوى حماية الخزنة'),
            LevelPicker(lvl: cl, onChanged: (v) => setState(() => cl = v)),
            const SizedBox(height: 6),
            const Text(
              'ملحوظة: وقت الفتح هيتحدد بالمستوى اللي تختاره هنا.',
              style: TextStyle(fontSize: 12, color: kMuted),
            ),
          ]),
        ),
      ],
      const SizedBox(height: 16),
      FilledButton.icon(
        style: kBtn,
        onPressed: busy ? null : (mk ? _create : _unlock),
        icon: busy
            ? const SizedBox(
                width: 18,
                height: 18,
                child: CircularProgressIndicator(strokeWidth: 2))
            : Icon(mk ? Icons.add : Icons.lock_open),
        label: Text(busy
            ? 'جارٍ التنفيذ...'
            : (mk ? 'إنشاء الخزنة' : 'فتح الخزنة')),
      ),
      if (err != null) Msg(err!),
      if (!mk && slots.length < VaultStore.maxSlots)
        Padding(
          padding: const EdgeInsets.only(top: 8),
          child: TextButton(
            onPressed: busy
                ? null
                : () => setState(() {
                      creating = true;
                      err = null;
                      pw.clear();
                      pw2.clear();
                    }),
            child: const Text('إنشاء خزنة جديدة'),
          ),
        ),
      if (creating && slots.isNotEmpty)
        TextButton(
          onPressed: busy
              ? null
              : () => setState(() {
                    creating = false;
                    err = null;
                    pw.clear();
                    pw2.clear();
                  }),
          child: const Text('رجوع'),
        ),
      const SizedBox(height: 8),
      TextButton.icon(
        onPressed: busy ? null : _import,
        icon: const Icon(Icons.download),
        label: const Text('استيراد نسخة احتياطية'),
      ),
      const SizedBox(height: 8),
      const Text(
        'الخزنة بتستخدم تشفير مزدوج (XChaCha20 + AES-256-GCM). كل خزنة ليها كلمة سر مستقلة. '
        'بتتقفل لوحدها لما تخرج من التطبيق أو بعد المدة المحددة في تاب «أدوات» من غير لمس. '
        'بعد 3 محاولات غلط بيتفعّل انتظار بيزيد مع كل محاولة.',
        style: TextStyle(fontSize: 12, color: kMuted, height: 1.5),
      ),
    ]);
  }

  @override
  Widget build(BuildContext context) {
    if (!loaded) return const Center(child: CircularProgressIndicator());
    final s = session;
    return s != null ? _open(s) : _locked();
  }
}

// ============================================================
//  تاب الأدوات والإعدادات
// ============================================================
class ToolsTab extends StatefulWidget {
  const ToolsTab({super.key});
  @override
  State<ToolsTab> createState() => _ToolsTabState();
}

class _ToolsTabState extends State<ToolsTab> {
  int len = 24;
  bool lower = true, upper = true, digits = true, symbols = true, noAmb = true;
  String gen = '';
  bool wiping = false;
  bool lockBusy = false;

  @override
  void initState() {
    super.initState();
    _gen();
    wipe.addListener(_clearGen);
  }

  @override
  void dispose() {
    wipe.removeListener(_clearGen);
    super.dispose();
  }

  void _clearGen() {
    if (!mounted) return;
    setState(() => gen = '');
  }

  void _gen() {
    gen = genPasswordWith(len,
        lower: lower,
        upper: upper,
        digits: digits,
        symbols: symbols,
        noAmbiguous: noAmb);
  }

  Future<void> _saveInt(String k, int v) async {
    try {
      final p = await SharedPreferences.getInstance();
      await p.setInt(k, v);
    } catch (_) {}
  }

  void _snack(String m) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(m)));
  }

  Future<void> _wipeAll() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: kCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(22)),
        title: const Text('مسح كل الخزن؟'),
        content: const Text(
            'هيتحذف كل اللي في الخزن نهائيًا من الموبايل ده. مفيش أي طريقة للرجوع فيه إلا لو معاك نسخة احتياطية.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('إلغاء'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: kBad),
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('امسح كل حاجة'),
          ),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    setState(() => wiping = true);
    try {
      idleLock.value++;
      await VaultStore.deleteAll();
      await Clipboard.setData(const ClipboardData(text: ''));
      vaultsChanged.value++;
      _snack('اتمسحت كل الخزن');
    } catch (_) {
      _snack('حصل خطأ أثناء المسح');
    } finally {
      if (mounted) setState(() => wiping = false);
    }
  }

  // بيتأكد من كلمة قفل التطبيق الحالية (مع تأخير المحاولات الغلط)
  Future<bool> _askCurrent() async {
    final cur = await showDialog<String>(
      context: context,
      builder: (_) =>
          const PwPromptDialog(title: 'اكتب كلمة قفل التطبيق الحالية'),
    );
    if (cur == null || !mounted) return false;
    final wait = await AppLockStore.lockedForMs();
    if (wait > 0) {
      _snack('محاولات غلط كتير. استنى ${(wait / 1000).ceil()} ثانية');
      return false;
    }
    final ok = await AppLockStore.verify(cur);
    if (ok) {
      await AppLockStore.noteOk();
    } else {
      await AppLockStore.noteFail();
      _snack('كلمة السر غلط');
    }
    return ok;
  }

  Future<void> _enableLock() async {
    if (lockBusy) return;
    setState(() => lockBusy = true);
    try {
      final np = await showDialog<String>(
        context: context,
        builder: (_) => const PwPromptDialog(
            title: 'كلمة قفل التطبيق الجديدة', confirm: true),
      );
      if (np == null || !mounted) return;
      await AppLockStore.setPassword(np);
      final p = await SharedPreferences.getInstance();
      await p.remove('lock_skip');
      appLockOn.value = true;
      appUnlocked.value = true;
      _snack('قفل التطبيق اتفعّل');
    } catch (_) {
      _snack('حصل خطأ أثناء التفعيل');
    } finally {
      if (mounted) setState(() => lockBusy = false);
    }
  }

  Future<void> _changeLock() async {
    if (lockBusy) return;
    setState(() => lockBusy = true);
    try {
      if (!await _askCurrent() || !mounted) return;
      final np = await showDialog<String>(
        context: context,
        builder: (_) => const PwPromptDialog(
            title: 'كلمة قفل التطبيق الجديدة', confirm: true),
      );
      if (np == null || !mounted) return;
      await AppLockStore.setPassword(np);
      _snack('اتغيّرت كلمة القفل');
    } catch (_) {
      _snack('حصل خطأ أثناء التغيير');
    } finally {
      if (mounted) setState(() => lockBusy = false);
    }
  }

  Future<void> _disableLock() async {
    if (lockBusy) return;
    setState(() => lockBusy = true);
    try {
      if (!await _askCurrent() || !mounted) return;
      await AppLockStore.remove();
      final p = await SharedPreferences.getInstance();
      await p.setBool('lock_skip', true);
      appLockOn.value = false;
      appUnlocked.value = true;
      _snack('قفل التطبيق اتوقّف');
    } catch (_) {
      _snack('حصل خطأ أثناء الإيقاف');
    } finally {
      if (mounted) setState(() => lockBusy = false);
    }
  }

  Widget _lockPanel() {
    return Panel(
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const SectionLabel('قفل التطبيق'),
        ValueListenableBuilder<bool>(
          valueListenable: appLockOn,
          builder: (c, on, _) {
            if (!on) {
              return Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'القفل مش شغّال: أي حد يفتح موبايلك يقدر يفتح التطبيق.',
                      style:
                          TextStyle(fontSize: 12.5, color: kMuted, height: 1.5),
                    ),
                    const SizedBox(height: 10),
                    FilledButton.icon(
                      style: kBtn,
                      onPressed: lockBusy ? null : _enableLock,
                      icon: const Icon(Icons.lock),
                      label: Text(
                          lockBusy ? 'جارٍ التنفيذ...' : 'تفعيل قفل التطبيق'),
                    ),
                  ]);
            }
            return Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Row(children: [
                    Icon(Icons.verified_user, color: kAccent, size: 20),
                    SizedBox(width: 8),
                    Text('القفل شغّال',
                        style: TextStyle(
                            color: kAccent, fontWeight: FontWeight.w700)),
                  ]),
                  const SizedBox(height: 12),
                  const SectionLabel('يتقفل بعد الخروج من التطبيق'),
                  ValueListenableBuilder<int>(
                    valueListenable: graceSecs,
                    builder: (c2, g, _) => SizedBox(
                      width: double.infinity,
                      child: SegmentedButton<int>(
                        showSelectedIcon: false,
                        segments: const [
                          ButtonSegment(value: 0, label: Text('فورًا')),
                          ButtonSegment(value: 30, label: Text('30 ث')),
                          ButtonSegment(value: 120, label: Text('2 د')),
                        ],
                        selected: {g},
                        onSelectionChanged: (s) {
                          graceSecs.value = s.first;
                          _saveInt('lockgrace', s.first);
                        },
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),
                  OutlinedButton.icon(
                    onPressed: lockBusy ? null : _changeLock,
                    icon: const Icon(Icons.password),
                    label: const Text('تغيير كلمة القفل'),
                  ),
                  const SizedBox(height: 8),
                  OutlinedButton.icon(
                    onPressed: lockBusy ? null : _disableLock,
                    icon: const Icon(Icons.lock_open),
                    label: const Text('إيقاف القفل'),
                  ),
                ]);
          },
        ),
      ]),
    );
  }

  Widget _sw(String label, bool value, ValueChanged<bool> onChanged) {
    return SwitchListTile(
      dense: true,
      contentPadding: EdgeInsets.zero,
      title: Text(label),
      value: value,
      onChanged: onChanged,
    );
  }

  @override
  Widget build(BuildContext context) {
    final bits = entropyBits(gen);
    return ListView(padding: pagePad, children: [
      const TabHeader(
        icon: Icons.tune,
        title: 'أدوات وإعدادات',
        subtitle: 'قفل التطبيق، ومولّد كلمات سر، والتحكم في الحافظة',
      ),
      const SizedBox(height: 16),
      _lockPanel(),
      const SizedBox(height: 16),
      Panel(
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const SectionLabel('مولّد كلمات السر'),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: kCard2,
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: kLine),
            ),
            child: SelectableText(
              gen.isEmpty ? '—' : gen,
              contextMenuBuilder: noMenu,
              textDirection: TextDirection.ltr,
              style: const TextStyle(
                  fontFamily: 'monospace', fontSize: 16, height: 1.4),
            ),
          ),
          const SizedBox(height: 8),
          StrengthMeter(bits),
          const SizedBox(height: 8),
          Text('الطول: $len'),
          Slider(
            value: len.toDouble(),
            min: 8,
            max: 64,
            divisions: 56,
            label: '$len',
            onChanged: (v) => setState(() {
              len = v.round();
              _gen();
            }),
          ),
          _sw('حروف صغيرة (a-z)', lower, (v) => setState(() {
                lower = v;
                _gen();
              })),
          _sw('حروف كبيرة (A-Z)', upper, (v) => setState(() {
                upper = v;
                _gen();
              })),
          _sw('أرقام (0-9)', digits, (v) => setState(() {
                digits = v;
                _gen();
              })),
          _sw('رموز (!@#...)', symbols, (v) => setState(() {
                symbols = v;
                _gen();
              })),
          _sw('تجنّب الحروف المتشابهة (l و I و O و 0 و 1)', noAmb,
              (v) => setState(() {
                    noAmb = v;
                    _gen();
                  })),
          const SizedBox(height: 8),
          Row(children: [
            Expanded(
              child: FilledButton.icon(
                style: kBtn,
                onPressed: () => setState(_gen),
                icon: const Icon(Icons.casino),
                label: const Text('توليد'),
              ),
            ),
            const SizedBox(width: 10),
            OutlinedButton.icon(
              style: OutlinedButton.styleFrom(
                minimumSize: const Size(52, 52),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(14)),
              ),
              onPressed: gen.isEmpty ? null : () => copySecure(context, gen),
              icon: const Icon(Icons.copy),
              label: const Text('نسخ'),
            ),
          ]),
        ]),
      ),
      const SizedBox(height: 16),
      Panel(
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const SectionLabel('القفل التلقائي للخزنة بعد'),
          ValueListenableBuilder<int>(
            valueListenable: autoLockMin,
            builder: (c, v, _) => SizedBox(
              width: double.infinity,
              child: SegmentedButton<int>(
                showSelectedIcon: false,
                segments: const [
                  ButtonSegment(value: 1, label: Text('1 د')),
                  ButtonSegment(value: 2, label: Text('2 د')),
                  ButtonSegment(value: 5, label: Text('5 د')),
                  ButtonSegment(value: 10, label: Text('10 د')),
                ],
                selected: {v},
                onSelectionChanged: (s) {
                  autoLockMin.value = s.first;
                  _saveInt('autolock', s.first);
                },
              ),
            ),
          ),
          const SizedBox(height: 16),
          const SectionLabel('مسح الحافظة تلقائيًا بعد النسخ'),
          ValueListenableBuilder<int>(
            valueListenable: clipSecs,
            builder: (c, v, _) => SizedBox(
              width: double.infinity,
              child: SegmentedButton<int>(
                showSelectedIcon: false,
                segments: const [
                  ButtonSegment(value: 15, label: Text('15 ث')),
                  ButtonSegment(value: 30, label: Text('30 ث')),
                  ButtonSegment(value: 60, label: Text('60 ث')),
                ],
                selected: {v},
                onSelectionChanged: (s) {
                  clipSecs.value = s.first;
                  _saveInt('clip', s.first);
                },
              ),
            ),
          ),
          const SizedBox(height: 12),
          OutlinedButton.icon(
            onPressed: () async {
              await Clipboard.setData(const ClipboardData(text: ''));
              _snack('اتمسحت الحافظة');
            },
            icon: const Icon(Icons.content_paste_off),
            label: const Text('امسح الحافظة دلوقتي'),
          ),
        ]),
      ),
      const SizedBox(height: 16),
      Container(
        width: double.infinity,
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: kBadSoft,
          borderRadius: BorderRadius.circular(18),
          border: Border.all(color: kBadLine),
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const Row(children: [
            Icon(Icons.warning_amber, color: kBad),
            SizedBox(width: 8),
            Text('منطقة خطر',
                style: TextStyle(color: kBad, fontWeight: FontWeight.w700)),
          ]),
          const SizedBox(height: 8),
          const Text(
            'مسح كل الخزن من الموبايل ده نهائيًا. اعمل نسخة احتياطية الأول من قايمة الخزنة (⋮ ← تصدير نسخة احتياطية).',
            style: TextStyle(fontSize: 12.5, color: kMuted, height: 1.5),
          ),
          const SizedBox(height: 10),
          OutlinedButton.icon(
            style: OutlinedButton.styleFrom(
              foregroundColor: kBad,
              side: const BorderSide(color: kBadLine),
            ),
            onPressed: wiping ? null : _wipeAll,
            icon: const Icon(Icons.delete_forever),
            label: const Text('مسح كل الخزن من الموبايل'),
          ),
        ]),
      ),
    ]);
  }
}

// ============================================================
//  قفل التطبيق
//  - كلمة القفل مش بتتخزّن: بنخزّن رسالة ثابتة مشفّرة بمفتاح مشتق منها (Argon2id)
//    والتحقق = فك الرسالة بنجاح
//  - تأخير متزايد بعد 3 محاولات غلط
// ============================================================
class AppLockStore {
  static const String _k = 'applock.v1';
  static const String _tag = 'KC-APPLOCK-OK';

  static Future<bool> isSet() async {
    final p = await SharedPreferences.getInstance();
    return p.containsKey(_k);
  }

  static Future<void> setPassword(String pw) async {
    final lvl = levels[0];
    final salt = _rand(16);
    final nonce = _rand(_nonceLen(3));
    final header = (BytesBuilder()
          ..add([0x4B, 0x4C, 1, 3])
          ..add(_u32(lvl.mem))
          ..addByte(lvl.iter)
          ..addByte(1)
          ..add(salt))
        .toBytes();
    final key = await compute(_derive, <String, Object>{
      'pw': pw,
      'salt': salt,
      'mem': lvl.mem,
      'iter': lvl.iter,
      'len': _keyLen(3),
    });
    try {
      final blob = await _seal(utf8.encode(_tag), key, 3, nonce, header);
      final out = BytesBuilder()
        ..add(header)
        ..add(nonce)
        ..add(blob);
      final p = await SharedPreferences.getInstance();
      await p.setString(_k, base64Url.encode(out.toBytes()));
    } finally {
      wipeBytes(key);
    }
  }

  static Future<bool> verify(String pw) async {
    List<int>? key;
    try {
      final p = await SharedPreferences.getInstance();
      final raw = p.getString(_k);
      if (raw == null) return false;
      final b = base64Url.decode(base64Url.normalize(raw));
      final nl = _nonceLen(3);
      if (b.length < 26 + nl + 16 ||
          b[0] != 0x4B ||
          b[1] != 0x4C ||
          b[2] != 1 ||
          b[3] != 3) {
        return false;
      }
      final mem = ByteData.sublistView(b, 4, 8).getUint32(0);
      final iter = b[8];
      if (mem < 8192 ||
          mem > kMaxMem ||
          iter < 1 ||
          iter > kMaxIter ||
          b[9] != 1) {
        return false;
      }
      final header = b.sublist(0, 26);
      final salt = b.sublist(10, 26);
      final nonce = b.sublist(26, 26 + nl);
      final blob = b.sublist(26 + nl);
      key = await compute(_derive, <String, Object>{
        'pw': pw,
        'salt': salt,
        'mem': mem,
        'iter': iter,
        'len': _keyLen(3),
      });
      final clear = await _open(blob, key, 3, nonce, header);
      return utf8.decode(clear) == _tag;
    } catch (_) {
      return false;
    } finally {
      if (key != null) wipeBytes(key);
    }
  }

  static Future<void> remove() async {
    final p = await SharedPreferences.getInstance();
    await p.remove(_k);
    await p.remove('lock_fails');
    await p.remove('lock_until');
  }

  static Future<int> lockedForMs() async {
    final p = await SharedPreferences.getInstance();
    final until = p.getInt('lock_until') ?? 0;
    final left = until - DateTime.now().millisecondsSinceEpoch;
    return left > 0 ? left : 0;
  }

  static Future<void> noteFail() async {
    final p = await SharedPreferences.getInstance();
    final fails = (p.getInt('lock_fails') ?? 0) + 1;
    await p.setInt('lock_fails', fails);
    if (fails >= 3) {
      final secs = min(900, 5 * (1 << min(fails - 3, 8)));
      await p.setInt(
          'lock_until', DateTime.now().millisecondsSinceEpoch + secs * 1000);
    }
  }

  static Future<void> noteOk() async {
    final p = await SharedPreferences.getInstance();
    await p.remove('lock_fails');
    await p.remove('lock_until');
  }
}

// نافذة بتطلب كلمة سر (أو كلمة جديدة مع تأكيد)
class PwPromptDialog extends StatefulWidget {
  const PwPromptDialog({super.key, required this.title, this.confirm = false});
  final String title;
  final bool confirm;
  @override
  State<PwPromptDialog> createState() => _PwPromptDialogState();
}

class _PwPromptDialogState extends State<PwPromptDialog> {
  final a = TextEditingController();
  final b = TextEditingController();
  String? err;

  @override
  void dispose() {
    a.dispose();
    b.dispose();
    super.dispose();
  }

  void _ok() {
    if (a.text.isEmpty) {
      setState(() => err = 'اكتب كلمة السر');
      return;
    }
    if (widget.confirm) {
      if (isWeakLock(a.text)) {
        setState(() => err = lockWeakMsg);
        return;
      }
      if (a.text != b.text) {
        setState(() => err = 'كلمتين السر مش متطابقتين');
        return;
      }
    }
    Navigator.of(context).pop(a.text);
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: kCard,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(22)),
      title: Text(widget.title),
      content: SingleChildScrollView(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const SizedBox(height: 6),
          PwField(a),
          if (widget.confirm) ...[
            const SizedBox(height: 10),
            PwField(b, label: 'تأكيد كلمة السر'),
          ],
          if (err != null) Msg(err!),
        ]),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('إلغاء'),
        ),
        FilledButton(onPressed: _ok, child: const Text('تأكيد')),
      ],
    );
  }
}

// البوابة: بتعرض شاشة القفل (أو إعداد أول مرة) قبل ما تظهر الشاشة الرئيسية
class AppLockGate extends StatefulWidget {
  const AppLockGate({super.key, required this.child});
  final Widget child;
  @override
  State<AppLockGate> createState() => _AppLockGateState();
}

class _AppLockGateState extends State<AppLockGate>
    with WidgetsBindingObserver {
  final pw = TextEditingController();
  final pw2 = TextEditingController();
  bool loaded = false;
  bool needSetup = false;
  bool busy = false;
  String? err;
  DateTime? _pausedAt;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    appLockOn.addListener(_onChange);
    appUnlocked.addListener(_onChange);
    appIdle.addListener(_lockNow);
    _init();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    appLockOn.removeListener(_onChange);
    appUnlocked.removeListener(_onChange);
    appIdle.removeListener(_lockNow);
    pw.dispose();
    pw2.dispose();
    super.dispose();
  }

  Future<void> _init() async {
    try {
      final p = await SharedPreferences.getInstance();
      final isSet = p.containsKey('applock.v1');
      final skipped = p.getBool('lock_skip') ?? false;
      final g = p.getInt('lockgrace') ?? 0;
      graceSecs.value = const [0, 30, 120].contains(g) ? g : 0;
      appLockOn.value = isSet;
      appUnlocked.value = !isSet;
      needSetup = !isSet && !skipped;
    } catch (_) {}
    if (mounted) setState(() => loaded = true);
  }

  void _lockNow() {
    if (appLockOn.value && appUnlocked.value) appUnlocked.value = false;
  }

  void _onChange() {
    if (!mounted) return;
    if (appLockOn.value && !appUnlocked.value) {
      Navigator.of(context).popUntil((r) => r.isFirst);
      pw.clear();
      pw2.clear();
      err = null;
    }
    setState(() {});
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused) {
      _pausedAt = pickerOpen ? null : DateTime.now();
      if (!pickerOpen && graceSecs.value == 0) _lockNow();
    } else if (state == AppLifecycleState.resumed) {
      final t = _pausedAt;
      _pausedAt = null;
      if (t != null &&
          DateTime.now().difference(t).inSeconds >= graceSecs.value) {
        _lockNow();
      }
    }
  }

  Future<void> _unlock() async {
    if (busy) return;
    if (pw.text.isEmpty) {
      setState(() => err = 'اكتب كلمة السر');
      return;
    }
    setState(() {
      busy = true;
      err = null;
    });
    try {
      final wait = await AppLockStore.lockedForMs();
      if (wait > 0) {
        if (mounted) {
          setState(() => err =
              'محاولات غلط كتير. استنى ${(wait / 1000).ceil()} ثانية وجرّب تاني');
        }
        return;
      }
      final ok = await AppLockStore.verify(pw.text);
      if (!mounted) return;
      if (ok) {
        await AppLockStore.noteOk();
        pw.clear();
        appUnlocked.value = true;
      } else {
        await AppLockStore.noteFail();
        final w = await AppLockStore.lockedForMs();
        if (mounted) {
          setState(() => err = w > 0
              ? 'كلمة السر غلط. استنى ${(w / 1000).ceil()} ثانية قبل المحاولة الجاية'
              : 'كلمة السر غلط');
        }
      }
    } catch (_) {
      if (mounted) setState(() => err = 'حصل خطأ أثناء الفتح');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> _enable() async {
    if (busy) return;
    if (isWeakLock(pw.text)) {
      setState(() => err = lockWeakMsg);
      return;
    }
    if (pw.text != pw2.text) {
      setState(() => err = 'كلمتين السر مش متطابقتين');
      return;
    }
    setState(() {
      busy = true;
      err = null;
    });
    try {
      await AppLockStore.setPassword(pw.text);
      pw.clear();
      pw2.clear();
      needSetup = false;
      appLockOn.value = true;
      appUnlocked.value = true;
    } catch (_) {
      if (mounted) setState(() => err = 'حصل خطأ أثناء التفعيل');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> _skip() async {
    try {
      final p = await SharedPreferences.getInstance();
      await p.setBool('lock_skip', true);
    } catch (_) {}
    pw.clear();
    pw2.clear();
    if (mounted) {
      setState(() {
        needSetup = false;
        err = null;
      });
    }
  }

  Future<void> _forgot() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: kCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(22)),
        title: const Text('نسيت كلمة القفل؟'),
        content: const Text(
            'مفيش طريقة لاسترجاعها. الحل الوحيد إنك تمسح كل بيانات التطبيق: كل الخزن هتتمسح، وتقدر تستورد نسخة احتياطية بعد كده. تكمّل؟'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('إلغاء'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: kBad),
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('امسح كل حاجة'),
          ),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    try {
      await AppLockStore.remove();
      await VaultStore.deleteAll();
      final p = await SharedPreferences.getInstance();
      await p.remove('lock_skip');
      vaultsChanged.value++;
      needSetup = true;
      appLockOn.value = false;
      appUnlocked.value = true;
    } catch (_) {
      if (mounted) setState(() => err = 'حصل خطأ أثناء المسح');
    }
    if (mounted) setState(() {});
  }

  Widget _setup() {
    return Scaffold(
      body: SafeArea(
        child: ListView(padding: pagePad, children: [
          const SizedBox(height: 32),
          const Icon(Icons.shield, size: 64, color: kAccent),
          const SizedBox(height: 12),
          const Text('أمّن التطبيق',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 22, fontWeight: FontWeight.w800)),
          const SizedBox(height: 8),
          const Text(
            'اختار كلمة قفل عشان محدش غيرك يفتح التطبيق. مش هتتخزّن نفسها، وتقدر تغيّرها أو توقّفها بعدين من تاب «أدوات».',
            textAlign: TextAlign.center,
            style: TextStyle(color: kMuted, height: 1.5),
          ),
          const SizedBox(height: 24),
          PwField(pw, label: 'كلمة قفل التطبيق', onChanged: () => setState(() {})),
          const SizedBox(height: 12),
          PwField(pw2, label: 'تأكيد كلمة القفل'),
          const SizedBox(height: 16),
          FilledButton.icon(
            style: kBtn,
            onPressed: busy ? null : _enable,
            icon: busy
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.lock),
            label: Text(busy ? 'جارٍ التفعيل...' : 'تفعيل القفل'),
          ),
          if (err != null) Msg(err!),
          const SizedBox(height: 8),
          TextButton(
            onPressed: busy ? null : _skip,
            child: const Text('تخطي دلوقتي (مش مستحسن)'),
          ),
        ]),
      ),
    );
  }

  Widget _locked() {
    return Scaffold(
      body: SafeArea(
        child: ListView(padding: pagePad, children: [
          const SizedBox(height: 48),
          const Icon(Icons.lock, size: 64, color: kAccent),
          const SizedBox(height: 12),
          const Text('THE CRYPT',
              textAlign: TextAlign.center,
              style: TextStyle(
                  fontSize: 24, fontWeight: FontWeight.w800, letterSpacing: 4)),
          const SizedBox(height: 6),
          const Text('التطبيق مقفول',
              textAlign: TextAlign.center, style: TextStyle(color: kMuted)),
          const SizedBox(height: 28),
          PwField(pw, label: 'كلمة قفل التطبيق'),
          const SizedBox(height: 16),
          FilledButton.icon(
            style: kBtn,
            onPressed: busy ? null : _unlock,
            icon: busy
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.lock_open),
            label: Text(busy ? 'جارٍ التحقق...' : 'فتح'),
          ),
          if (err != null) Msg(err!),
          const SizedBox(height: 8),
          TextButton(
            onPressed: busy ? null : _forgot,
            child: const Text('نسيت كلمة السر؟'),
          ),
        ]),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (!loaded) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    if (needSetup) return _setup();
    if (appLockOn.value && !appUnlocked.value) return _locked();
    return widget.child;
  }
}