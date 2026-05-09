#  Chromium项目史上最大规模：Chrome 148一次性修复127个漏洞  
 奇安信 CERT   2026-05-09 10:52  
  
## 一、事件概述  
  
Chrome 148稳定版于2026年5月正式发布，Google一次性修复127个安全漏洞，其中3个严重（Critical）级别、31个高危（High）级别漏洞创下Chromium内核浏览器历史最高修复记录。此次更新涉及Blink、V8、ANGLE、GPU、Chromoting、WebRTC等核心组件，漏洞类型集中于释放后使用（Use-After-Free）、整数溢出、堆缓冲区溢出和越界读写等典型内存破坏类缺陷。奇安信威胁情报中心监测显示，攻击者可利用路过式攻击（Drive-by Attack）方式，通过恶意网页触发漏洞并实现远程代码执行或沙箱逃逸。  
## 二、严重漏洞技术分析  
### CVE-2026-7896：Blink引擎整数溢出  
  
**受影响组件：**  
Chrome渲染引擎Blink（布局计算模块）  
  
**影响：**  
远程攻击者通过诱导用户访问特制HTML页面触发整数溢出条件，进而引发堆内存损坏。整数溢出漏洞在浏览器攻击链中通常作为信息泄露或控制流劫持的触发点，攻击者可借此绕过ASLR等缓解机制。结合其他漏洞可构建完整的RCE攻击链。  
  
**发现与赏金：**  
外部安全研究人员于2026年3月发现并报告，获**$43,000**  
漏洞赏金。  
### CVE-2026-7897：Mobile组件释放后使用  
  
**受影响组件：**  
Chrome Mobile组件  
  
**影响：**  
释放后使用（UAF）漏洞是Chromium系浏览器的顽疾。当内存对象被释放后未被清空指针，攻击者可重新分配同类内存并构造恶意数据，当程序再次访问该对象时即可执行任意代码。该漏洞影响Chrome Mobile组件，位于特权上下文，理论上存在沙箱逃逸可能。  
  
**发现：**  
Google内部安全团队发现，未对外发放赏金。  
### CVE-2026-7898：Chromoting组件释放后使用  
  
**受影响组件：**  
Chromoting（Chrome远程桌面功能模块）  
  
**影响：**  
此组件以较高权限运行，且涉及系统进程交互。UAF漏洞若被成功利用，攻击者可实现从渲染进程到系统级的权限提升。结合Chrome多进程架构隔离机制被破坏的风险，攻击者可在受害者主机上建立持久化 foothold。  
  
**发现：**  
Google内部安全团队发现此漏洞。  
### CVE-2026-7899：V8引擎越界读写（CVSS 9.3）  
  
**受影响组件：**  
V8 JavaScript引擎（JIT编译器优化阶段）  
  
**影响：**  
越界读写漏洞可导致攻击者读写虚拟机内存空间外的任意内存区域，直接实现代码执行或敏感数据窃取。**CVSS评分高达9.3**  
，获本次更新最高单笔赏金**$55,000**  
，表明其技术复杂度和利用价值极高。  
## 三、高危漏洞全谱系梳理  
  
Chrome 148修复的高危漏洞呈现系统性分布特征，覆盖浏览器渲染管线全链条：  
<table><thead><tr style="background:#f0f7ff;"><th style="padding:8px 10px;border:1px solid #e0e0e0;text-align:left;font-weight:bold;color:#333;"><section><span leaf="">组件域</span></section></th><th style="padding:8px 10px;border:1px solid #e0e0e0;text-align:left;font-weight:bold;color:#333;"><section><span leaf="">漏洞类型</span></section></th><th style="padding:8px 10px;border:1px solid #e0e0e0;text-align:left;font-weight:bold;color:#333;"><section><span leaf="">风险影响</span></section></th></tr></thead><tbody><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">ANGLE</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">堆缓冲区溢出</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">图形渲染上下文破坏</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">SVG/DOM</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">释放后使用</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">渲染进程代码执行</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">GPU/Skia/Dawn</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">越界写入/未初始化使用</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">沙箱逃逸路径</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">V8</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">越界读写</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">JavaScript沙箱突破</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">WebRTC</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">释放后使用</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">实时通信数据泄露</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">ServiceWorker</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">策略验证不足</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">权限绕过</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">Media/Fonts</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">越界读取/输入验证不足</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">信息泄露/代码执行</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">DevTools</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">策略执行不足/数据验证缺陷</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">开发者工具滥用</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">PresentationAPI/InterestGroups</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">类型混淆</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">功能滥用/数据窃取</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">Passwords</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">内存破坏</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">凭证信息泄露</span></section></td></tr></tbody></table>  
**技术研判：**  
30余个高危漏洞集中于渲染引擎和JavaScript执行环境，表明Chromium内核在追求性能优化过程中持续积累历史债务。V8引擎作为攻击者必争之地，其$55,000赏金定价远超常规，反映出该类漏洞在野利用的紧迫性和利用门槛的相对可控性。  
## 四、威胁行为体关联分析  
### APT攻击利用路径  
  
Chrome零日漏洞历来是APT组织的首选入口。**2026年已有4个Chrome零日漏洞被修补**  
，意味着存在在野利用的活跃零日。从威胁情报维度分析：  
- **漏洞利用窗口期：**  
Chrome采用自动静默更新机制，但企业内网环境和版本管控需求导致大量终端存在版本滞后，漏洞公开后的数日至数周内构成高危窗口。  
  
- **攻击场景：**  
路过式下载攻击可通过水坑网站或定向钓鱼链接实施，受害者仅访问恶意页面即可触发完整利用链。  
  
- **目标画像：**  
浏览器漏洞通常针对情报目标的高价值人员（决策层、研发人员、安全运维），配合社工手段使用。  
  
### 关联威胁组织  
- **国家背景APT组织：**  
Chrome/Chromium漏洞是浏览器攻击套件的核心组件，可用于横向移动和持久化。  
  
- **商业 spyware 厂商：**  
NSO Group、Candiru等厂商曾多次利用Chrome零日漏洞构建移动端攻击链。  
  
- **供应链攻击者：**  
Chromium内核覆盖Chrome、Edge、Opera等主流浏览器，一个内核漏洞可影响数十亿终端。  
  
**关联风险：**  
用户大量使用Chrome、Edge（Chromium内核）等浏览器，且企业环境中常存在版本管理滞后的情况。  
## 五、漏洞利用战术演进  
### 攻击链构建模式  
  
[1] 社会工程/水坑攻击 → 诱导用户访问恶意页面  
  
[2] 渲染引擎漏洞(CVE-2026-7896) → 堆内存破坏/信息泄露  
  
[3] V8引擎漏洞(CVE-2026-7899) → JIT spraying/代码执行  
  
[4] 沙箱逃逸(CVE-2026-7897/98) → 系统权限提升  
  
[5] 持久化 → 植入后门/横向移动  
### MITRE ATT&CK 技术映射  
<table><thead><tr style="background:#fff5f5;"><th style="padding:7px 10px;border:1px solid #e0e0e0;text-align:left;font-weight:bold;color:#333;"><section><span leaf="">战术阶段</span></section></th><th style="padding:7px 10px;border:1px solid #e0e0e0;text-align:left;font-weight:bold;color:#333;"><section><span leaf="">技术编号</span></section></th><th style="padding:7px 10px;border:1px solid #e0e0e0;text-align:left;font-weight:bold;color:#333;"><section><span leaf="">技术名称</span></section></th></tr></thead><tbody><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">初始访问</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">T1189</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">路过式攻击</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">执行</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">T1203</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">利用漏洞攻击</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">持久化</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">T1547.001</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">启动项修改（潜在）</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">横向移动</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">T1210</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">利用漏洞利用进行横向移动</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">数据外泄</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">T1041</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">C2信道（潜在）</span></section></td></tr></tbody></table>### 战术趋势研判  
1. **漏洞组合化：**  
单一漏洞难以穿透Chrome多层缓解机制，攻击者倾向于打包多个漏洞构建攻击链。  
  
1. **JIT引擎成为焦点：**  
V8等JavaScript引擎的JIT编译优化逻辑复杂，是近年代码执行漏洞的主要来源。  
  
1. **沙箱逃逸优先级提升：**  
渲染进程沙箱被突破后，需要额外的特权升级漏洞实现系统控制。  
  
## 六、用户风险评估  
### 暴露面分析  
- **用户基数：**  
全球Chrome用户数量超20亿。  
  
- **版本分布：**  
企业内网环境、政府机构终端普遍存在版本滞后，部分终端运行Chrome 140-145版本。  
  
- **攻击面：**  
Web邮件、协同办公、云文档等高频率使用的Web应用成为水坑攻击的理想目标。  
  
### 实际威胁场景  
1. **鱼叉式钓鱼 + 浏览器漏洞：**  
针对特定人员的定向攻击中，恶意链接配合零日漏洞可实现零点击利用。  
  
1. **供应链投毒：**  
通过篡改开源组件或Chrome扩展程序，间接利用浏览器漏洞。  
  
1. **内网横移：**  
利用浏览器漏洞攻陷终端后，作为跳板访问内网资源。  
  
### 缓解建议  
- **立即行动：**  
所有Chrome/Edge Chromium浏览器更新至148.0.7778.96/97版本。  
  
- **企业部署：**  
通过MDM、组策略或SCCM批量推送更新，优先覆盖对外暴露的终端。  
  
- **网络侧检测：**  
监控异常Chrome进程崩溃日志（Dr. Watson），关注来自可疑域的WebRTC/Chromoting连接。  
  
- **EDR增强：**  
启用浏览器沙箱日志，监测异常的子进程创建和DLL加载行为。  
  
## 七、结论与研判  
  
Chrome 148一次性披露127个漏洞，是Chromium项目历史上最大规模的安全发布。3个严重漏洞（CVE-2026-7896/97/98）和CVSS 9.3分的V8越界漏洞表明，Chromium内核的内存安全问题呈系统性恶化趋势。从威胁情报视角判断：  
- 2026年已有4个Chrome零日被修补，暗示在野零日利用处于活跃状态；  
  
- V8引擎$55,000的赏金定价反映该漏洞已具备在野利用条件；  
  
- 渲染引擎、JavaScript引擎、远程桌面组件的漏洞集群为APT攻击链构建提供丰富选项。  
  
奇安信威胁情报中心将持续监控相关漏洞的在野利用情况，并同步更新至威胁情报平台。建议所有用户立即更新浏览器版本，企业安全团队应将此次更新纳入本周补丁管理优先级。  
## 八、技术附录  
  
**受影响版本：**  
Linux: 148.0.7778.96；Windows/macOS: 148.0.7778.96/97  
  
**赏金总额：**  
$138,000+（外部研究人员）；单笔最高$55,000  
  
关键CVE清单：  
<table><thead><tr style="background:#fff5f5;"><th style="padding:7px 10px;border:1px solid #e0e0e0;text-align:left;font-weight:bold;color:#333;"><section><span leaf="">CVE编号</span></section></th><th style="padding:7px 10px;border:1px solid #e0e0e0;text-align:left;font-weight:bold;color:#333;"><section><span leaf="">组件</span></section></th><th style="padding:7px 10px;border:1px solid #e0e0e0;text-align:left;font-weight:bold;color:#333;"><section><span leaf="">漏洞类型</span></section></th><th style="padding:7px 10px;border:1px solid #e0e0e0;text-align:left;font-weight:bold;color:#333;"><section><span leaf="">严重程度</span></section></th></tr></thead><tbody><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">CVE-2026-7896</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">Blink</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">整数溢出</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#e63946;font-weight:bold;"><section><span leaf="">Critical</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">CVE-2026-7897</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">Mobile</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">Use-After-Free</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#e63946;font-weight:bold;"><section><span leaf="">Critical</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">CVE-2026-7898</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">Chromoting</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">Use-After-Free</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#e63946;font-weight:bold;"><section><span leaf="">Critical</span></section></td></tr><tr><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">CVE-2026-7899</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">V8</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#333;"><section><span leaf="">越界读写</span></section></td><td style="padding:7px 10px;border:1px solid #e0e0e0;color:#e63946;font-weight:bold;"><section><span leaf="">Critical</span></section></td></tr></tbody></table>  
  
