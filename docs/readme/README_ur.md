<div dir="rtl">

<div align="center">

[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md)
· [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md) · **اردو**

# REA: ہر چیز کی ریورس انجینئرنگ

### بائنری فائلوں، ایپلی کیشنز اور runtime رویّے کی ریورس انجینئرنگ کے لیے ایک MCP۔

**کوئی پسندیدہ فیچر نظر آیا؟ سمجھیں کہ وہ بائنری سطح تک کیسے کام کرتا ہے۔**

[![npm version](https://img.shields.io/npm/v/rea-agents?style=flat-square&color=cb3837)](https://www.npmjs.com/package/rea-agents)
[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-5c4ee5?style=flat-square)](../mcp-contracts.md#generated-catalog)
[![Node.js requirements](https://img.shields.io/badge/Node.js-requirements-339933?style=flat-square&logo=nodedotjs&logoColor=white)](#آپ-کیا-تجزیہ-کر-سکتے-ہیں)
[![skills.sh](https://skills.sh/b/morluto/rea?style=flat-square)](https://skills.sh/morluto/rea/reverse-engineer-anything)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)
[![Discord](https://img.shields.io/discord/1556595354999332884?logo=discord&logoColor=white&label=Discord&color=5865F2)](https://discord.gg/GkcryMnJDM)

<a href="https://trendshift.io/repositories/82054?utm_source=repository-badge&amp;utm_medium=badge&amp;utm_campaign=badge-repository-82054" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/repositories/82054" alt="morluto%2Frea | Trendshift" width="250" height="55"/></a>

**[ویب سائٹ](https://rea.tools/) · [رہنما](https://rea.tools/guides/) · [نمائشی مثالیں](https://rea.tools/showcase/)**

[فوری آغاز](#فوری-آغاز) · [REA کیسے کام کرتا ہے](#rea-کیسے-کام-کرتا-ہے) · [آپ کیا تجزیہ کر سکتے ہیں](#آپ-کیا-تجزیہ-کر-سکتے-ہیں) · [نمائشی مثالیں](#نمائشی-مثالیں) · [عمومی سوالات](#عمومی-سوالات) · [دستاویزات](#دستاویزات)

<code>npx rea-agents setup</code>

</div>

> [!IMPORTANT]
> REA صرف [morluto/rea](https://github.com/morluto/rea)،
> [rea.tools](https://rea.tools/) یا [rea-agents npm package](https://www.npmjs.com/package/rea-agents)
> سے حاصل کریں۔ تنصیب اور ریلیز کے لیے انہی سرکاری ذرائع کے روابط استعمال کریں۔
> ملتے جلتے repository نام یا نقل شدہ README سے یہ ثابت نہیں ہوتا کہ کوئی ڈاؤن لوڈ سرکاری ہے۔

<div align="center">

<br />

<img src="../assets/rea-hopper-analysis.png" alt="REA مقامی بائنری کا معائنہ کرتے ہوئے Hopper کے اندر اپنا analysis bridge شروع کر رہا ہے" width="1200" />

<br /><br />

<table aria-label="REA کمیونٹی">
<tr>
<td align="center" width="360">
  <a href="https://discord.gg/GkcryMnJDM">
    <img src="../assets/discord.svg" height="42" alt="Discord" /><br />
    <strong>ریورس انجینئرنگ کمیونٹی میں شامل ہوں</strong>
  </a><br />
  <sub>Discord · سوال و جواب · تجربات اور دریافتیں</sub>
</td>
</tr>
</table>

<br />

</div>

---

کسی ایپ میں ایسا فیچر دیکھا جسے آپ اپنی پروڈکٹ میں شامل کرنا چاہتے ہیں؟ اپنے agent سے کہیں کہ REA کے ذریعے اس کی جانچ کرے۔ یہ source code کے بغیر بھی ایپ کا معائنہ کر سکتا ہے، فیچر کے کام کرنے کا طریقہ سمجھا سکتا ہے، شواہد دکھا سکتا ہے اور آپ کے project کے لیے اس کا متبادل بنا سکتا ہے۔

REA آپ کے agent کو native binaries، JavaScript اور Electron apps، .NET assemblies اور websites کے معائنے کے tools فراہم کرتا ہے۔ یہی tools آپ اپنے terminal سے بھی استعمال کر سکتے ہیں۔ تجزیہ مقامی طور پر ہوتا ہے، اور نتائج میں ہر نتیجے کے پیچھے شواہد اور حدود شامل ہوتی ہیں۔

Setup آپ کے agent میں REA رجسٹر کرتا ہے اور اس سے مطابقت رکھنے والی workflow ہدایات نصب کرتا ہے۔ Native analysis کے لیے پہلے سے نصب Hopper، Ghidra یا IDA استعمال کیے جا سکتے ہیں؛ منظوری کے بعد setup اختیاری طور پر Hopper نصب کر سکتا ہے۔ Static JavaScript analysis کے لیے native analysis engine درکار نہیں۔

> **[REA کی ویب سائٹ دیکھیں](https://rea.tools/)** — setup ہدایات، تصاویر والے رہنما اور حقیقی case studies کے لیے۔

## فوری آغاز

Linux پر Ghidra، JADX، firmware tool launches اور static JavaScript/Electron analysis کو process ownership جانچنے کے لیے REA کے `PATH` میں procps-compatible `ps` درکار ہے۔ حل کے مراحل `docs/installation.md` کے "Linux owned-process prerequisite" حصے میں ہیں۔

### اپنا agent ترتیب دیں

Node.js اور npm نصب کرنے کے بعد یہ command چلائیں:

```bash
npx rea-agents setup
```

اپنے agents منتخب کریں، مجوزہ تبدیلیوں کا جائزہ لیں اور ان کی منظوری دیں۔ Setup موجودہ configuration کا backup رکھتے ہوئے REA کا MCP server اور متعلقہ workflow ہدایات شامل کرتا ہے۔ اس کے بعد اپنا agent دوبارہ شروع کریں۔

Setup، Claude Code، Codex، Cursor، Gemini CLI، Grok Build اور [دیگر agents](../installation.md#supported-agents) کو سپورٹ کرتا ہے۔ Provider configuration اور دستی MCP registration کے لیے [تنصیب اور setup](../installation.md) دیکھیں۔

### اپنے agent سے کہیں

```text
Notes app میں search کیسے کام کرتا ہے، اس کے شواہد دکھائیں، اور میرے project کے لیے اسی جیسا فیچر بنائیں۔
```

`Notes` کی جگہ اپنی مطلوبہ app اور اس فیچر کا نام دیں جسے آپ سمجھنا چاہتے ہیں۔

### Terminal استعمال کریں

Extract کی گئی JavaScript/Electron app directory یا ASAR کا معائنہ کریں:

```bash
npx -y rea-agents@latest analyze-javascript-application /absolute/path/to/app --json
```

نتیجے میں modules، imports، Electron boundaries اور ان کے شواہد شامل ہیں۔ `/absolute/path/to/app` کی جگہ اپنے target کا path دیں؛ مثلاً Windows پر `"D:/apps/example"`۔

روزمرہ استعمال کے لیے `rea` command نصب کریں:

```bash
npm install --global rea-agents
rea --help
```

Native analysis سے پہلے ایک provider ترتیب دیں۔ Native commands، provider انتخاب، snapshots اور scripting کے لیے [CLI اور Evidence رہنما](../cli.md) دیکھیں۔

### REA اپ ڈیٹ کریں

REA میں تیزی سے تبدیلیاں آتی ہیں اور نئی ریلیز میں اکثر bug fixes شامل ہوتے ہیں۔ اپنی installation تازہ رکھیں۔

`npm install --global` یا `bun add --global` سے نصب CLI کے لیے:

```bash
rea update
```

`rea --update` اسی تصدیق شدہ workflow کا alias ہے اور وہی global output flags قبول کرتا ہے۔ دوسرے command controls کے ساتھ اسے استعمال کرتے وقت `rea update` چلائیں۔

Updater commands، stdout اور stderr کو ملا کر زیادہ سے زیادہ 4 MiB محفوظ رکھتے ہیں۔ حد سے بڑے metadata replies کو command ختم ہونے کے بعد مسترد کیا جاتا ہے؛ verbose installs محدود diagnostics کے ساتھ جاری رہتی ہیں۔ انسانی progress output، terminal backpressure کا خیال رکھتا ہے اور بھیجی گئی writes مکمل ہونے کا انتظار کرتا ہے۔

Bun کی global updates کے لیے Bun 1.2.17 یا اس کے بعد کا ورژن ضروری ہے۔ پرانے Bun کے ساتھ `rea update` سے پہلے Bun کو دستی طور پر اپ گریڈ کریں۔

اپنے agent کی registrations اور skill تازہ کرنے کے لیے update کی طرف سے دکھایا گیا setup command چلائیں۔

اگر آپ `npx` استعمال کرتے ہیں تو agent setup تازہ کرنے کے لیے:

```bash
npx rea-agents@latest setup
```

Setup کی تبدیلیوں کا جائزہ لیں اور agent دوبارہ شروع کریں۔ ایک بار کے CLI commands کے لیے command سے پہلے `npx rea-agents@latest` استعمال کریں۔ Bun کے ساتھ، `npx rea-agents@latest` کی جگہ `bunx rea-agents@latest` استعمال کریں۔

## REA کیسے کام کرتا ہے

آپ کا agent MCP کے ذریعے REA کو target کا معائنہ کرنے اور متعلقہ code کا سراغ لگانے کے لیے بلاتا ہے۔ REA شواہد سمیت نتائج واپس کرتا ہے۔ Agent ان نتائج سے مزید سوالات کرتا، رویّے کی وضاحت کرتا، یا implementation لکھ کر اس کی جانچ کرتا ہے۔ CLI commands بھی یہی workflows استعمال کرتے ہیں۔

![REA تحقیق کا بہاؤ: آپ کا agent مقامی target کے بارے میں پوچھتا ہے، REA analysis tools سے اس کا معائنہ اور code کا سراغ لگاتا ہے، پھر agent واپس ملنے والے code، references اور نامعلوم پہلوؤں سے وضاحت، implementation اور tests تیار کرتا ہے۔](../../website/public/assets/figures/rea-investigation-flow.svg)

[مکمل سائز کی تصویر کھولیں](../../website/public/assets/figures/rea-investigation-flow.svg)۔

<a id="current-status"></a>

## آپ کیا تجزیہ کر سکتے ہیں

REA کو Node.js 22.x (>=22.19)، 24.x (>=24.11) یا 26+ اور npm درکار ہیں۔ اضافی tools اور host support، target کے مطابق مختلف ہوتے ہیں:

| Target                     | REA کے نتائج                                                                       | تقاضے اور رہنما                                                                                                                   |
| -------------------------- | ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Native binaries            | Pseudocode، assembly، strings، symbols، calls اور references                       | Hopper، Ghidra یا IDA؛ [native analysis](../native-investigation.md)                                                              |
| Offline ELF layout         | Sections، segments، اصل symbols/relocations اور static mitigation امیدوار          | Linux x64 پر caller-supplied pwntools؛ [binary diagnostics](../binary-diagnostics.md)                                             |
| Go binaries                | شامل compiler version، modules، replacements اور build settings                    | Built-in static ELF/PE/thin Mach-O معائنہ؛ Go نصب کرنا ضروری نہیں                                                                 |
| Rust binaries              | شامل cargo-auditable crate names، versions، sources اور dependency edges           | Built-in static ELF/PE/thin Mach-O معائنہ؛ [Rust binaries](../rust-binaries.md)                                                   |
| WASM artifact              | توثیق، sections، عین import/export WAT forms اور decoded WAT                       | Caller-supplied WABT 1.0.42؛ `inspect_wasm_artifact`                                                                              |
| EVM bytecode               | Dispatch selectors، byte offsets، اخذ کردہ arguments اور mutability                | Linux x64 پر مقامی raw/hex carrier؛ [offline EVM رہنما](../evm-bytecode.md)                                                       |
| SQLite databases           | Tables، columns، indexes، views، triggers اور منتخب عام-table rows                 | مقامی database/WAL snapshot؛ native SQLite حدود کے ساتھ Node.js 24.x >=24.15 یا 26+                                               |
| Recorded Linux crashes     | Raw notes، ہر recorded thread کے registers/signals اور اختیاری mapping امیدوار     | Linux x64 پر caller-supplied pwntools؛ اختیاری GDB/pwndbg؛ [recorded crashes](../recorded-crashes.md)                             |
| JavaScript / Electron      | Modules، imports، source maps، routes، IPC اور native add-on تعلقات                | Node.js اور npm؛ Linux: procps-compatible `ps`؛ [application analysis](../javascript-application-workflows.md)                    |
| Websites                   | Page structure، scripts، network observations اور مطلوبہ screenshots               | Chrome-family browser؛ [browser analysis](../browser-observation.md)                                                              |
| محفوظ شدہ network captures | Requests، responses، ظاہر شدہ payloads اور source locations                        | HAR یا Fiddler Everywhere SAZ؛ Linux پر native mitmproxy کے لیے mitmdump؛ [capture رہنما](../web-network-captures.md)             |
| .NET assemblies            | Metadata، CIL instructions، اعلان شدہ native dependencies اور build comparisons     | کوئی نہیں (صرف static)؛ [.NET رہنما](../managed-code-analysis.md)                                                                 |
| Android APKs               | Manifest declarations، classes، decompiled methods اور references                  | Linux/macOS/Windows x64 پر headless JADX اور مکمل JDK؛ [Android رہنما](../android-analysis.md)                                    |
| Android devices            | Devices، packages، processes، logs، dumps، screen captures اور APK/file transfers  | Caller-supplied adb (emulator یا hardware)؛ [ADB رہنما](../adb-device-analysis.md)                                                |
| JEB projects               | Engine-backed project units، artifact digests اور type/method pseudo-code          | Caller-started JEB client جو MCP فراہم کرے، REA_JEB_MCP_URL سے منتخب؛ [JEB رہنما](../jeb-analysis.md)                             |
| Android resources          | Decoded manifest، string tables، locales اور version facts                         | Caller-supplied Apktool launcher؛ [resources رہنما](../apktool-resource-analysis.md)                                              |
| Flutter apps               | Dart snapshot hash، فی ABI library digests اور engine build provenance             | کوئی نہیں (static APK parsing)؛ [Flutter رہنما](../flutter-analysis.md)                                                           |
| Firmware                   | Regions، extraction نتائج اور native-analysis handoffs                             | Linux پر Binwalk / Unblob؛ [firmware رہنما](../firmware-analysis.md)                                                              |
| Recorded packets           | منتخب fields، بار بار آنے والی values، filters اور decode-as rules                 | Linux: TShark 4.x + prlimit؛ [capture رہنما](../packet-captures.md)                                                               |
| Packet summaries           | Endpoints، DNS، TLS SNI، protocol distribution اور HTTP requests                   | Caller-supplied tshark اور capinfos (Linux پر تصدیق شدہ)؛ [pcap رہنما](../pcap-analysis.md)                                       |
| Recorded logic signals     | Decoder annotations، sample ranges اور diagnostics                                 | Linux: sigrok-cli 0.7.2 + prlimit؛ [signal recordings](../signal-recordings.md)                                                   |
| Packages اور resources     | File inventories، digests، plists، Apple bundle anatomy اور extracted resources    | [Artifact اور JavaScript رہنما](../javascript-artifact-reconstruction.md)، [Apple applications](../apple-application-analysis.md) |
| Process behavior           | Terminal output، interactions، exit اور filesystem observations، اور runs کا تقابل | Linux/macOS پر native PTY؛ [process capture](../process-capture.md)                                                               |

Static JavaScript اور .NET معائنہ، فراہم کردہ فائلوں کو application چلائے بغیر پڑھتا ہے۔ Runtime capture آپ کی user permissions کے تحت منتخب target چلاتا یا اس سے تعامل کرتا ہے؛ ہر runtime رہنما اس کے اثرات بیان کرتا ہے۔

Offline native-binary معائنے کے لیے REA، caller-supplied GNU objdump اور Rizin کو بھی سپورٹ کرتا ہے۔ Provider setup، CLI commands اور Evidence کی حدود کے لیے [reverse-engineering tools رہنما](../reverse-engineering-tools.md) دیکھیں۔ REA ان providers کو نصب یا اپ ڈیٹ نہیں کرتا۔

<a id="choosing-a-deep-analysis-provider"></a>

Native formats اور host support، provider کے لحاظ سے مختلف ہیں۔ [Hopper اور Ghidra setup](../installation.md#hopper)، [IDA رہنما](../ida-provider.md) (اختیاری native MCP bridge سمیت)، [Kuna decompiler رہنما](../kuna-provider.md)، اور [تجرباتی Windows Ghidra support](../windows-ghidra-p0.md) دیکھیں۔

Ghidra، [16-bit DOS analysis](../ghidra-dos.md) بھی سپورٹ کرتا ہے۔ بڑی binaries کے لیے `REA_GHIDRA_STARTUP_TIMEOUT_MS` یا `REA_HOPPER_STARTUP_TIMEOUT_MS` سے provider کی startup deadline بڑھائیں۔ Provider کے انتخاب کے لیے [CLI رہنما](../cli.md#choose-a-provider) دیکھیں۔ تازہ ترین npm release کے بعد شامل features کے لیے [release availability](../installation.md#released-package-and-main) دیکھیں۔

## نمائشی مثالیں

[![DX-Ball sound-pan، Notion clipboard-bridge اور TH04 bullet-ring کی مثالیں](../assets/rea-showcases.png)](https://rea.tools/showcase/)

### DX-Ball: sound-pan calculation کی تشکیلِ نو

کسی sound call کو اس کے position-to-pan helper تک trace کریں، instructions کا معائنہ کریں، اور نامکمل pseudocode کو C میں تبدیل کریں۔ یہ تشکیلِ نو 3,205 اصل-x86 cases پر کامیاب ہوتی ہے اور تمام 63 compiled function bytes سے مطابقت رکھتی ہے۔

[Case study پڑھیں](https://rea.tools/showcase/dx-ball/) · [Reconstruction repository](https://github.com/N0zoM1z0/dx-ball)

### Notion: Electron clipboard bridge کا سراغ

Renderer کی clipboard API تلاش کریں، اسے preload اور IPC کے ذریعے main process تک follow کریں، اور rich clipboard format کا معائنہ کریں۔

[Case study پڑھیں](https://rea.tools/showcase/notion/)

### TH04: DOS bullet-ring calculation کی بازیافت

اصل PC-98 game کی 16-bit instructions کا معائنہ کریں، fixed اور aimed angle calculations بازیافت کریں، اور reconstructed C++ کا تاریخی compiler output سے تقابل کریں۔

[Case study پڑھیں](https://rea.tools/showcase/th04/) · [Reconstruction repository](https://github.com/N0zoM1z0/th04)

اگر آپ نے REA کسی دلچسپ چیز پر استعمال کیا ہے تو ہمیں دکھائیں۔ اپنا target، سوال، REA سے ملنے والی مدد اور دریافت سمیت [issue](https://github.com/morluto/rea/issues) یا [pull request](https://github.com/morluto/rea/pulls) میں شریک کریں۔

## عمومی سوالات

<details>
<summary><strong>REA کون سے agents کے ساتھ کام کرتا ہے؟</strong></summary>

کوئی بھی agent جو مقامی MCP servers سپورٹ کرتا ہو۔ Setup، [سپورٹ شدہ agents](../installation.md#supported-agents) ترتیب دیتا ہے؛ دوسرے clients [دستی MCP registration](../installation.md#mcp-registry) استعمال کر سکتے ہیں۔

</details>

<details>
<summary><strong>کیا مجھے Hopper، Ghidra یا IDA درکار ہیں؟</strong></summary>

گہری native analysis کے لیے ان میں سے ایک درکار ہے۔ Static JavaScript اور .NET معائنہ native analysis engine کے بغیر کام کرتا ہے۔ منظوری کے بعد setup Hopper نصب کر سکتا ہے؛ Ghidra اور IDA کے لیے آپ کی موجودہ installation استعمال ہوتی ہے۔ [Provider setup](../installation.md#hopper) دیکھیں۔

</details>

<details>
<summary><strong>کیا مجھے Hopper پہلے شروع کرنا ہوگا؟</strong></summary>

جب کسی operation کو ضرورت ہو تو REA، Hopper شروع کرتا ہے۔ macOS پر پہلی بار چلانے پر demo mode منتخب کرنے یا license فعال کرنے کا dialog دکھائی دے سکتا ہے۔ اپنی پہلی CLI/MCP operation یا unattended job سے پہلے اسی user session میں اسے مکمل کریں۔ ضرورت پڑنے پر Hopper خود کھولیں۔ [Hopper startup اور troubleshooting](../installation.md#launcher-paths-and-troubleshooting) دیکھیں۔

</details>

<details>
<summary><strong>skills.sh سے skill نصب کرنے پر کیا ہوتا ہے؟</strong></summary>

Skill، آپ کے agent کو investigation کی ہدایات فراہم کرتا ہے۔ REA کا MCP server رجسٹر کرنے اور متعلقہ ہدایات نصب کرنے کے لیے `npx rea-agents setup` چلائیں، پھر agent دوبارہ شروع کریں۔ [صرف skill کی تنصیب](../installation.md#skill-only-installation) دیکھیں۔

</details>

<details>
<summary><strong>REA کون سا code واپس کرتا ہے؟</strong></summary>

Native analysis، pseudocode اور assembly واپس کرتا ہے۔ JavaScript/Electron analysis، modules اور ان کے باہمی تعلقات بازیافت کرتا ہے۔ آپ کا agent ان نتائج سے implementation لکھتا اور جانچتا ہے؛ [نمائشی مثالوں](#نمائشی-مثالیں) میں مکمل مثالیں ہیں۔

</details>

<details>
<summary><strong>کیا REA میری app upload کرتا ہے؟</strong></summary>

REA targets کا مقامی طور پر تجزیہ کرتا ہے۔ آپ کا agent، tool results وصول کرتا ہے اور اس کے model provider کی اپنی data policy ہوتی ہے۔

</details>

<details>
<summary><strong>اگر کوئی bug ملے تو کیا کروں؟</strong></summary>

پہلے اپ ڈیٹ کریں؛ ممکن ہے حالیہ release میں اس کا حل آ چکا ہو۔

`npm install --global` یا `bun add --global` سے نصب CLI کے لیے:

```bash
rea update
```

`npx` کے ذریعے agent setup کے لیے:

```bash
npx rea-agents@latest setup
```

اگر آپ agent استعمال کرتے ہیں تو [setup تازہ کریں](#rea-اپ-ڈیٹ-کریں) اور اسے دوبارہ شروع کریں۔ پھر وہی کام دہرائیں۔ مسئلہ برقرار رہے تو اپنے REA version، target type، دوبارہ پیدا کرنے کے مراحل اور error output کے ساتھ [issue کھولیں](https://github.com/morluto/rea/issues)۔

</details>

## دستاویزات

ویب سائٹ کے [عملی رہنماؤں](https://rea.tools/guides/) سے آغاز کریں۔ مخصوص اختیارات، تقاضوں اور result contracts کے لیے:

- [تنصیب اور setup](../installation.md): agent registration، provider configuration، updates اور uninstall۔
- [تیاری اور troubleshooting](../installation.md#check-readiness-for-your-task): کسی agent یا analysis engine کی تشخیص۔
- [CLI اور Evidence](../cli.md): commands، provider انتخاب، snapshots، import/export اور exit statuses۔
- [MCP contracts](../mcp-contracts.md) اور [agent prompts](../mcp-prompts.md): tool results، sessions اور رہنمائی کے ساتھ investigations۔
- [Tool catalog](../mcp-contracts.md#generated-catalog): tools، providers اور CLI commands کی خودکار فہرست۔
- [Roadmap](../roadmap.md): منصوبہ بند کام اور capability trackers۔

Vulnerabilities کی اطلاع [SECURITY.md](../../SECURITY.md) کے ذریعے دیں۔

## Stars کی تاریخ

🎉 **GitHub پر 300,000 stars — شکریہ!**

REA استعمال کرنے، bugs رپورٹ کرنے، features کی درخواست دینے، builds آزمانے اور fixes میں حصہ لینے والے سب لوگوں کا شکریہ۔

<a href="https://www.star-history.com/?repos=morluto%2Frea&amp;type=date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=morluto/rea&amp;type=date&amp;theme=dark&amp;legend=top-left" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=morluto/rea&amp;type=date" />
    <img alt="REA GitHub stars کی تاریخ" src="https://api.star-history.com/chart?repos=morluto/rea&amp;type=date" />
  </picture>
</a>

## دستبرداری

ذمہ دارانہ استعمال کی ہدایات کے لیے [DISCLAIMER.md](../../DISCLAIMER.md) دیکھیں۔

غیر قانونی یا غیر مجاز استعمال کے بارے میں project کا مؤقف، REA کے تمام versions، distribution channels اور platforms پر لاگو ہوتا ہے؛ ہر copy کے ساتھ اس کے متعلقہ licenses برقرار رہتے ہیں۔

REA قانونی تحقیق، تعلیم، interoperability، software preservation، اور ایسے software کے تجزیے کے لیے ہے جس کے آپ مالک ہوں یا جس کی جانچ کی آپ کو اجازت ہو۔

## تعاون

ہم REA میں آپ کی مدد کے خواہش مند ہیں! Bug رپورٹ کرنے یا feature تجویز کرنے کے لیے [issue کھولیں](https://github.com/morluto/rea/issues)، یا code اور docs بہتر بنانے کے لیے [pull request بھیجیں](https://github.com/morluto/rea/pulls)۔

Development setup اور checks کے لیے [CONTRIBUTING.md](../../CONTRIBUTING.md)، verification lanes کے لیے [testing](../testing.md)، اور project structure کے لیے [architecture map](../architecture.mermaid) دیکھیں۔

## لائسنس

[MIT](../../LICENSE)

REA کا تحریر کردہ code، MIT کے تحت licensed ہے۔ تیسرے فریق کے مواد پر ان کے اپنے licenses اور copyright notices لاگو ہوتے ہیں؛ dependencies کی فہرست، محفوظ license texts اور external-tool شرائط کے لیے [Third-party notices](../../THIRD_PARTY_NOTICES.md) دیکھیں۔

**تجارتی tools**، بشمول IDA Pro / Hex-Rays decompilers، Hopper اور JEB، کو ان کے متعلقہ licenses کے تحت قانونی طور پر حاصل کرنا اور استعمال کی اجازت رکھنا آپ کی ذمہ داری ہے۔ REA کسی tool کا license، key یا activation entitlement فراہم نہیں کرتا۔ Trials اور demos پر بھی vendor کی شرائط لاگو ہوتی ہیں، بشمول user، feature، automation اور output sharing کی پابندیاں۔ Cracked copies، چوری شدہ keys، غیر مجاز key sharing اور license پابندیوں سے بچنے کی اجازت نہیں ہے۔ یہ رہنمائی MIT یا تیسرے فریق کے licenses میں تبدیلی نہیں کرتی۔

</div>
