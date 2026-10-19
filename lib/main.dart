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

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  ErrorWidget.builder = (details) => Directionality(
        textDirection: TextDirection.ltr,
        child: Material(
          color: Colors.black,
          child: SafeArea(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: Text('Error:\n${_short(details.exceptionAsString())}',
                  style: const TextStyle(color: Colors.redAccent)),
            ),
          ),
        ),
      );
  runApp(const VaultApp());
}

class Level {
  const Level(this.name, this.mem, this.iter);
  final String name;
  final int mem, iter;
}

const levels = [
  Level('عادي', 19456, 2),
  Level('قوي', 65536, 3),
  Level('أقصى', 131072, 3),
];

// أقصى قيم مسموح بيها وقت فك التشفير (حماية من نصوص معدّلة بتحجز ذاكرة ضخمة)
const int kMaxMem = 131072;
const int kMaxIter = 4;

final ValueNotifier<int> wipe = ValueNotifier<int>(0);
bool pickerOpen = false;
const weakMsg =
    'كلمة السر ضعيفة: لازم 10 حروف على الأقل ومتنوعة ومن غير كلمات شائعة. استخدم زر 🎲';
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

bool isWeak(String p) {
  if (p.length < 10) return true;
  final l = p.toLowerCase();
  if (_commonWords.any((w) => l.contains(w))) return true;
  if (p.split('').toSet().length < 5) return true;
  return entropyBits(p) < 45;
}

String _short(String s) => s.length > 300 ? s.substring(0, 300) : s;

Cipher _cipher(int id) =>
    id == 1 ? Xchacha20.poly1305Aead() : AesGcm.with256bits();

Uint8List _rand(int n) {
  final r = Random.secure();
  return Uint8List.fromList(List<int>.generate(n, (_) => r.nextInt(256)));
}

Uint8List _u32(int v) => (ByteData(4)..setUint32(0, v)).buffer.asUint8List();

Future<List<int>> _derive(Map<String, Object> a) async {
  final kdf = Argon2id(
    memory: a['mem'] as int,
    parallelism: 1,
    iterations: a['iter'] as int,
    hashLength: 32,
  );
  final key = await kdf.deriveKeyFromPassword(
    password: a['pw'] as String,
    nonce: a['salt'] as List<int>,
  );
  return key.extractBytes();
}

Future<String> encryptText(
    String text, String pw, int algoId, Level lvl) async {
  final salt = _rand(16);
  final nonce = _rand(algoId == 1 ? 24 : 12);
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
  });
  final box = await _cipher(algoId).encrypt(
    utf8.encode(text),
    secretKey: SecretKey(keyBytes),
    nonce: nonce,
    aad: header,
  );
  final out = BytesBuilder()
    ..add(header)
    ..add(box.cipherText)
    ..add(box.mac.bytes);
  return 'KC1.${base64Url.encode(out.toBytes())}';
}

Future<String> decryptText(String input, String pw) async {
  final s = input.replaceAll(RegExp(r'\s'), '');
  if (!s.startsWith('KC1.')) throw const FormatException('format');
  final b = base64Url.decode(base64Url.normalize(s.substring(4)));
  if (b.length < 26 + 12 + 16 || b[0] != 0x4B || b[1] != 0x43 || b[2] != 1) {
    throw const FormatException('format');
  }
  final algoId = b[3];
  if (algoId != 1 && algoId != 2) throw const FormatException('algo');
  final mem = ByteData.sublistView(b, 4, 8).getUint32(0);
  final iter = b[8];
  if (mem < 8192 || mem > kMaxMem || iter < 1 || iter > kMaxIter || b[9] != 1) {
    throw const FormatException('params');
  }
  final hLen = 26 + (algoId == 1 ? 24 : 12);
  if (b.length < hLen + 16) throw const FormatException('format');
  final header = b.sublist(0, hLen);
  final salt = b.sublist(10, 26);
  final nonce = b.sublist(26, hLen);
  final ct = b.sublist(hLen, b.length - 16);
  final mac = b.sublist(b.length - 16);
  final keyBytes = await compute(_derive, <String, Object>{
    'pw': pw,
    'salt': salt,
    'mem': mem,
    'iter': iter,
  });
  final clear = await _cipher(algoId).decrypt(
    SecretBox(ct, nonce: nonce, mac: Mac(mac)),
    secretKey: SecretKey(keyBytes),
    aad: header,
  );
  return utf8.decode(clear);
}

// ---------- تشفير الملفات (صيغة KF) ----------
// الهيدر: [0x4B,0x46,1,algo] + mem(4) + iter(1) + 1 + salt(16) + nonce(12|24)
// الباقي: ciphertext + mac(16)
// المحتوى قبل التشفير: nameLen(4) + اسم الملف + بيانات الملف

bool _isKcf(Uint8List b) =>
    b.length >= 26 + 12 + 16 &&
    b[0] == 0x4B &&
    b[1] == 0x46 &&
    b[2] == 1 &&
    (b[3] == 1 || b[3] == 2);

Future<Uint8List> _encBytesJob(Map<String, Object> a) async {
  final data = a['data'] as Uint8List;
  final pw = a['pw'] as String;
  final algoId = a['algo'] as int;
  final mem = a['mem'] as int;
  final iter = a['iter'] as int;
  final salt = _rand(16);
  final nonce = _rand(algoId == 1 ? 24 : 12);
  final hb = BytesBuilder()
    ..add([0x4B, 0x46, 1, algoId])
    ..add(_u32(mem))
    ..addByte(iter)
    ..addByte(1)
    ..add(salt)
    ..add(nonce);
  final header = hb.toBytes();
  final keyBytes = await _derive(<String, Object>{
    'pw': pw,
    'salt': salt,
    'mem': mem,
    'iter': iter,
  });
  final box = await _cipher(algoId).encrypt(
    data,
    secretKey: SecretKey(keyBytes),
    nonce: nonce,
    aad: header,
  );
  final out = BytesBuilder()
    ..add(header)
    ..add(box.cipherText)
    ..add(box.mac.bytes);
  return out.toBytes();
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
    final hLen = 26 + (algoId == 1 ? 24 : 12);
    if (b.length < hLen + 16) return null;
    final header = b.sublist(0, hLen);
    final salt = b.sublist(10, 26);
    final nonce = b.sublist(26, hLen);
    final ct = b.sublist(hLen, b.length - 16);
    final mac = b.sublist(b.length - 16);
    final keyBytes = await _derive(<String, Object>{
      'pw': pw,
      'salt': salt,
      'mem': mem,
      'iter': iter,
    });
    final clear = await _cipher(algoId).decrypt(
      SecretBox(ct, nonce: nonce, mac: Mac(mac)),
      secretKey: SecretKey(keyBytes),
      aad: header,
    );
    return Uint8List.fromList(clear);
  } catch (_) {
    return null;
  }
}

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

String genPassword([int n = 20]) {
  const a =
      'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#\$%^&*-_=+?';
  final r = Random.secure();
  return List<String>.generate(n, (_) => a[r.nextInt(a.length)]).join();
}

Future<void> copySecure(BuildContext c, String text) async {
  await Clipboard.setData(ClipboardData(text: text));
  if (c.mounted) {
    ScaffoldMessenger.of(c).showSnackBar(const SnackBar(
        content: Text('اتنسخ، وهيتمسح من الحافظة بعد 30 ثانية')));
  }
  Timer(const Duration(seconds: 30), () async {
    final d = await Clipboard.getData(Clipboard.kTextPlain);
    if (d?.text == text) await Clipboard.setData(const ClipboardData(text: ''));
  });
}

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
        colorScheme: ColorScheme.fromSeed(
            seedColor: const Color(0xFF00C853), brightness: Brightness.dark),
      ),
      builder: (c, child) => Directionality(
          textDirection: TextDirection.rtl,
          child: child ?? const SizedBox.shrink()),
      home: const VaultHome(),
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

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _loadSecure();
  }

  Future<void> _loadSecure() async {
    try {
      final p = await SharedPreferences.getInstance();
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
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused && !pickerOpen) wipe.value++;
  }

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 4,
      child: Scaffold(
        appBar: AppBar(
          title: const Text('THE CRYPT'),
          actions: [
            IconButton(
              icon: Icon(secure ? Icons.shield : Icons.shield_outlined),
              tooltip:
                  secure ? 'منع لقطات الشاشة: شغّال' : 'منع لقطات الشاشة: موقوف',
              onPressed: _toggleSecure,
            ),
          ],
          bottom: const TabBar(tabs: [
            Tab(icon: Icon(Icons.lock), text: 'تشفير'),
            Tab(icon: Icon(Icons.lock_open), text: 'فك التشفير'),
            Tab(icon: Icon(Icons.folder_zip), text: 'الملفات'),
            Tab(icon: Icon(Icons.inventory_2), text: 'خزنتي'),
          ]),
        ),
        body: const TabBarView(
            children: [EncryptTab(), DecryptTab(), FilesTab(), VaultTab()]),
      ),
    );
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
      onChanged: (_) => widget.onChanged?.call(),
      decoration: InputDecoration(
        labelText: widget.label,
        border: const OutlineInputBorder(),
        suffixIcon: Row(mainAxisSize: MainAxisSize.min, children: [
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
  const OutBox(this.text, {super.key});
  final String text;
  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          SelectableText(text, style: const TextStyle(fontSize: 15)),
          Align(
            alignment: AlignmentDirectional.centerEnd,
            child: TextButton.icon(
              onPressed: () => copySecure(context, text),
              icon: const Icon(Icons.copy),
              label: const Text('نسخ'),
            ),
          ),
        ]),
      ),
    );
  }
}

class EncryptTab extends StatefulWidget {
  const EncryptTab({super.key});
  @override
  State<EncryptTab> createState() => _EncryptTabState();
}

class _EncryptTabState extends State<EncryptTab>
    with AutomaticKeepAliveClientMixin<EncryptTab> {
  final text = TextEditingController();
  final pw = TextEditingController();
  int algo = 1, lvl = 1;
  String? out, err;
  bool busy = false;

  @override
  bool get wantKeepAlive => true;

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
    super.build(context);
    final bits = entropyBits(pw.text);
    final label = strengthLabel(bits);
    return ListView(padding: const EdgeInsets.all(16), children: [
      TextField(
        controller: text,
        maxLines: 6,
        decoration: const InputDecoration(
            labelText: 'النص المراد تشفيره', border: OutlineInputBorder()),
      ),
      const SizedBox(height: 12),
      PwField(pw, generate: true, onChanged: () => setState(() {})),
      const SizedBox(height: 6),
      LinearProgressIndicator(value: (bits / 100).clamp(0.0, 1.0)),
      Text('قوة كلمة السر: $label (${bits.round()} بت)'),
      const SizedBox(height: 12),
      const Text('الخوارزمية'),
      SegmentedButton<int>(
        segments: const [
          ButtonSegment(value: 1, label: Text('XChaCha20')),
          ButtonSegment(value: 2, label: Text('AES-256-GCM')),
        ],
        selected: {algo},
        onSelectionChanged: (v) => setState(() => algo = v.first),
      ),
      const SizedBox(height: 8),
      const Text('مستوى الحماية (أعلى = أبطأ وأصعب على المخترق)'),
      SegmentedButton<int>(
        segments: [
          for (var i = 0; i < levels.length; i++)
            ButtonSegment(value: i, label: Text(levels[i].name)),
        ],
        selected: {lvl},
        onSelectionChanged: (v) => setState(() => lvl = v.first),
      ),
      const SizedBox(height: 16),
      FilledButton.icon(
        onPressed: busy ? null : _go,
        icon: busy
            ? const SizedBox(
                width: 18,
                height: 18,
                child: CircularProgressIndicator(strokeWidth: 2))
            : const Icon(Icons.lock),
        label: Text(busy ? 'جارٍ التشفير...' : 'تشفير'),
      ),
      if (err != null)
        Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Text(err!, style: const TextStyle(color: Colors.redAccent)),
        ),
      if (out != null) OutBox(out!),
      const SizedBox(height: 16),
      const Text(
        'Argon2id لاشتقاق المفتاح + تشفير مُصادَق (AEAD). مفتاح ونونس جديدين لكل رسالة، '
        'وأي تعديل في النص المشفّر أو إعداداته بيفشّل فك التشفير.',
        style: TextStyle(fontSize: 12, color: Colors.grey),
      ),
    ]);
  }
}

class DecryptTab extends StatefulWidget {
  const DecryptTab({super.key});
  @override
  State<DecryptTab> createState() => _DecryptTabState();
}

class _DecryptTabState extends State<DecryptTab>
    with AutomaticKeepAliveClientMixin<DecryptTab> {
  final input = TextEditingController();
  final pw = TextEditingController();
  String? out, err;
  bool busy = false;

  @override
  bool get wantKeepAlive => true;

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
    super.build(context);
    return ListView(padding: const EdgeInsets.all(16), children: [
      TextField(
        controller: input,
        maxLines: 6,
        decoration: InputDecoration(
          labelText: 'النص المشفّر (يبدأ بـ KC1.)',
          border: const OutlineInputBorder(),
          suffixIcon: IconButton(
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
        onPressed: busy ? null : _go,
        icon: busy
            ? const SizedBox(
                width: 18,
                height: 18,
                child: CircularProgressIndicator(strokeWidth: 2))
            : const Icon(Icons.lock_open),
        label: Text(busy ? 'جارٍ فك التشفير...' : 'فك التشفير'),
      ),
      if (err != null)
        Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Text(err!, style: const TextStyle(color: Colors.redAccent)),
        ),
      if (out != null) OutBox(out!),
    ]);
  }
}

// ---------- تاب الملفات ----------

class FilesTab extends StatefulWidget {
  const FilesTab({super.key});
  @override
  State<FilesTab> createState() => _FilesTabState();
}

class _FilesTabState extends State<FilesTab>
    with AutomaticKeepAliveClientMixin<FilesTab> {
  static const int maxBytes = 20 * 1024 * 1024;
  final pw = TextEditingController();
  bool enc = true;
  int algo = 1, lvl = 1;
  String? path, fname, err, ok;
  int? size;
  bool busy = false;

  @override
  bool get wantKeepAlive => true;

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
    super.build(context);
    final bits = entropyBits(pw.text);
    return ListView(padding: const EdgeInsets.all(16), children: [
      SegmentedButton<bool>(
        segments: const [
          ButtonSegment(
              value: true, label: Text('تشفير ملف'), icon: Icon(Icons.lock)),
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
      const SizedBox(height: 12),
      OutlinedButton.icon(
        onPressed: busy ? null : _pick,
        icon: const Icon(Icons.attach_file),
        label: Text(enc ? 'اختار الملف المراد تشفيره' : 'اختار الملف المشفّر'),
      ),
      if (fname != null)
        Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Text('${fname!} (${_fmtSize(size ?? 0)})'),
        ),
      const SizedBox(height: 12),
      PwField(pw, generate: enc, onChanged: () => setState(() {})),
      if (enc) ...[
        const SizedBox(height: 6),
        LinearProgressIndicator(value: (bits / 100).clamp(0.0, 1.0)),
        Text('قوة كلمة السر: ${strengthLabel(bits)} (${bits.round()} بت)'),
        const SizedBox(height: 12),
        const Text('الخوارزمية'),
        SegmentedButton<int>(
          segments: const [
            ButtonSegment(value: 1, label: Text('XChaCha20')),
            ButtonSegment(value: 2, label: Text('AES-256-GCM')),
          ],
          selected: {algo},
          onSelectionChanged: (v) => setState(() => algo = v.first),
        ),
        const SizedBox(height: 8),
        const Text('مستوى الحماية'),
        SegmentedButton<int>(
          segments: [
            for (var i = 0; i < levels.length; i++)
              ButtonSegment(value: i, label: Text(levels[i].name)),
          ],
          selected: {lvl},
          onSelectionChanged: (v) => setState(() => lvl = v.first),
        ),
      ],
      const SizedBox(height: 16),
      FilledButton.icon(
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
      if (err != null)
        Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Text(err!, style: const TextStyle(color: Colors.redAccent)),
        ),
      if (ok != null)
        Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Text(ok!, style: const TextStyle(color: Colors.greenAccent)),
        ),
      const SizedBox(height: 16),
      const Text(
        'الملف المشفّر بيتحفظ بامتداد .kcf واسم الملف الأصلي بيتخزّن جواه مشفّر. '
        'الحد الأقصى لحجم الملف 20 ميجا.',
        style: TextStyle(fontSize: 12, color: Colors.grey),
      ),
    ]);
  }
}

// ---------- الخزنة ----------

class SecureWindow {
  static const _ch = MethodChannel('vault/secure');
  static Future<void> set(bool on) async {
    try {
      await _ch.invokeMethod('setSecure', {'on': on});
    } catch (_) {}
  }
}

class Session {
  Session(this.slot, this.key, this.header, this.items);
  final String slot;
  final Uint8List key, header;
  List<Map<String, dynamic>> items;
}

class VaultStore {
  static const int maxSlots = 5;

  static Future<Uint8List> _key(
          String pw, List<int> salt, int mem, int iter) async =>
      Uint8List.fromList(await compute(_derive, <String, Object>{
        'pw': pw,
        'salt': salt,
        'mem': mem,
        'iter': iter,
      }));

  static Future<void> _q = Future<void>.value();

  static Future<void> save(Session s) {
    final f = _q.then((_) => _saveNow(s));
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
    final nonce = _rand(24);
    final box = await _cipher(1).encrypt(
      utf8.encode(jsonEncode(s.items)),
      secretKey: SecretKey(s.key),
      nonce: nonce,
      aad: s.header,
    );
    final out = BytesBuilder()
      ..add(s.header)
      ..add(nonce)
      ..add(box.cipherText)
      ..add(box.mac.bytes);
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

  static Future<Session> create(
      String slot, String pw, List<Map<String, dynamic>> items) async {
    final lvl = levels[1];
    final salt = _rand(16);
    final header = (BytesBuilder()
          ..add([0x4B, 0x56, 1, 1])
          ..add(_u32(lvl.mem))
          ..addByte(lvl.iter)
          ..addByte(1)
          ..add(salt))
        .toBytes();
    final s =
        Session(slot, await _key(pw, salt, lvl.mem, lvl.iter), header, items);
    await save(s);
    return s;
  }

  static Future<Session?> tryOpen(String slot, String pw) async {
    try {
      final p = await SharedPreferences.getInstance();
      final raw = p.getString(slot);
      if (raw == null) return null;
      final b = base64Url.decode(base64Url.normalize(raw));
      if (b.length < 26 + 24 + 16) return null;
      if (b[0] != 0x4B || b[1] != 0x56 || b[2] != 1 || b[3] != 1) return null;
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
      final nonce = b.sublist(26, 50);
      final ct = b.sublist(50, b.length - 16);
      final mac = b.sublist(b.length - 16);
      final key = await _key(pw, salt, mem, iter);
      final clear = await _cipher(1).decrypt(
        SecretBox(ct, nonce: nonce, mac: Mac(mac)),
        secretKey: SecretKey(key),
        aad: header,
      );
      final list = jsonDecode(utf8.decode(clear)) as List;
      final items = <Map<String, dynamic>>[
        for (final e in list) Map<String, dynamic>.from(e as Map),
      ];
      return Session(slot, key, header, items);
    } catch (_) {
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
      title: Text(widget.initial == null ? 'عنصر جديد' : 'تعديل العنصر'),
      content: SizedBox(
        width: double.maxFinite,
        child: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            TextField(
              controller: t,
              decoration: const InputDecoration(
                  labelText: 'العنوان', border: OutlineInputBorder()),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: u,
              autocorrect: false,
              enableSuggestions: false,
              decoration: const InputDecoration(
                  labelText: 'اسم المستخدم / الإيميل',
                  border: OutlineInputBorder()),
            ),
            const SizedBox(height: 10),
            PwField(p, generate: true, label: 'كلمة السر / السر'),
            const SizedBox(height: 10),
            TextField(
              controller: n,
              maxLines: 4,
              decoration: const InputDecoration(
                  labelText: 'ملاحظات', border: OutlineInputBorder()),
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
      required this.onEdit,
      required this.onDelete});
  final Map<String, dynamic> item;
  final VoidCallback onEdit, onDelete;
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
    return Card(
      child: ExpansionTile(
        title: Text(title.isEmpty ? '(بدون عنوان)' : title),
        subtitle: user.isEmpty ? null : Text(user),
        childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
        expandedCrossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (user.isNotEmpty)
            Row(children: [
              Expanded(child: SelectableText(user)),
              IconButton(
                icon: const Icon(Icons.copy),
                tooltip: 'نسخ اسم المستخدم',
                onPressed: () => copySecure(context, user),
              ),
            ]),
          if (secret.isNotEmpty)
            Row(children: [
              Expanded(
                child: show
                    ? SelectableText(secret)
                    : const Text('••••••••••••'),
              ),
              IconButton(
                icon: Icon(show ? Icons.visibility_off : Icons.visibility),
                onPressed: () => setState(() => show = !show),
              ),
              IconButton(
                icon: const Icon(Icons.copy),
                tooltip: 'نسخ',
                onPressed: () => copySecure(context, secret),
              ),
            ]),
          if (note.isNotEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 6),
              child: SelectableText(note),
            ),
          Row(mainAxisAlignment: MainAxisAlignment.end, children: [
            TextButton.icon(
              onPressed: widget.onEdit,
              icon: const Icon(Icons.edit),
              label: const Text('تعديل'),
            ),
            TextButton.icon(
              onPressed: widget.onDelete,
              icon: const Icon(Icons.delete),
              label: const Text('حذف'),
            ),
          ]),
        ],
      ),
    );
  }
}

class VaultTab extends StatefulWidget {
  const VaultTab({super.key});
  @override
  State<VaultTab> createState() => _VaultTabState();
}

class _VaultTabState extends State<VaultTab>
    with AutomaticKeepAliveClientMixin<VaultTab> {
  final pw = TextEditingController();
  final pw2 = TextEditingController();
  Session? session;
  List<String> slots = const [];
  bool loaded = false;
  bool creating = false;
  bool busy = false;
  String? err;
  int _epoch = 0;

  @override
  bool get wantKeepAlive => true;

  @override
  void initState() {
    super.initState();
    wipe.addListener(_lock);
    _refreshSlots();
  }

  @override
  void dispose() {
    wipe.removeListener(_lock);
    pw.dispose();
    pw2.dispose();
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
    final wasOpen = session != null;
    session = null;
    pw.clear();
    pw2.clear();
    if (!mounted) return;
    if (wasOpen) Navigator.of(context).popUntil((r) => r.isFirst);
    setState(() {
      err = null;
      creating = false;
    });
  }

  Future<void> _unlock() async {
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
      final s = await VaultStore.openAny(pw.text);
      if (!mounted || ep != _epoch) return;
      if (s == null) {
        setState(() => err = 'كلمة السر غلط');
      } else {
        pw.clear();
        setState(() => session = s);
      }
    } catch (_) {
      if (mounted) setState(() => err = 'حصل خطأ أثناء فتح الخزنة');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> _create() async {
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
          if (mounted) setState(() => err = 'كلمة السر دي مستخدمة في خزنة تانية');
          return;
        }
      }
      final s = await VaultStore.create(slot, pw.text, <Map<String, dynamic>>[]);
      if (!mounted || ep != _epoch) return;
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
    if (r == null || cur == null || !identical(cur, s) || i >= cur.items.length) {
      return;
    }
    setState(() => cur.items[i] = r);
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
    final ok = await _confirm('تحذف الخزنة كلها نهائيًا؟ مفيش أي طريقة للرجوع فيها.');
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

  Widget _open(Session s) {
    return Column(children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(16, 8, 8, 0),
        child: Row(children: [
          Expanded(
            child: Text('الخزنة مفتوحة (${s.items.length})',
                style: Theme.of(context).textTheme.titleMedium),
          ),
          IconButton(
            icon: const Icon(Icons.add),
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
            },
            itemBuilder: (_) => const [
              PopupMenuItem<String>(value: 'del', child: Text('حذف الخزنة')),
            ],
          ),
        ]),
      ),
      Expanded(
        child: s.items.isEmpty
            ? const Center(child: Text('الخزنة فاضية. اضغط + عشان تضيف عنصر.'))
            : ListView.builder(
                padding: const EdgeInsets.all(12),
                itemCount: s.items.length,
                itemBuilder: (c, i) => ItemTile(
                  key: ObjectKey(s.items[i]),
                  item: s.items[i],
                  onEdit: () => _edit(i),
                  onDelete: () => _delete(i),
                ),
              ),
      ),
    ]);
  }

  Widget _locked() {
    final mk = creating || slots.isEmpty;
    final bits = entropyBits(pw.text);
    return ListView(padding: const EdgeInsets.all(16), children: [
      const SizedBox(height: 8),
      const Icon(Icons.inventory_2, size: 56),
      const SizedBox(height: 8),
      Text(
        mk ? 'إنشاء خزنة جديدة' : 'الخزنة مقفولة',
        textAlign: TextAlign.center,
        style: Theme.of(context).textTheme.titleLarge,
      ),
      const SizedBox(height: 16),
      PwField(pw, generate: mk, onChanged: () => setState(() {})),
      if (mk) ...[
        const SizedBox(height: 6),
        LinearProgressIndicator(value: (bits / 100).clamp(0.0, 1.0)),
        Text('قوة كلمة السر: ${strengthLabel(bits)} (${bits.round()} بت)'),
        const SizedBox(height: 12),
        PwField(pw2, label: 'تأكيد كلمة السر'),
      ],
      const SizedBox(height: 16),
      FilledButton.icon(
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
      if (err != null)
        Padding(
          padding: const EdgeInsets.only(top: 8),
          child: Text(err!, style: const TextStyle(color: Colors.redAccent)),
        ),
      if (!mk && slots.length < VaultStore.maxSlots)
        TextButton(
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
      const SizedBox(height: 16),
      const Text(
        'كل خزنة ليها كلمة سر مستقلة. لو نسيت كلمة السر مفيش أي طريقة لاسترجاع البيانات. '
        'الخزنة بتتقفل لوحدها لما تخرج من التطبيق.',
        style: TextStyle(fontSize: 12, color: Colors.grey),
      ),
    ]);
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    if (!loaded) return const Center(child: CircularProgressIndicator());
    final s = session;
    return s != null ? _open(s) : _locked();
  }
}