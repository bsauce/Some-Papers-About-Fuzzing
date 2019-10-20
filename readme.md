# 最新顶会fuzz论文分享

分享一下读过的最新的fuzzing论文，目前是用Xmind记录的，可能过于详细了些，未来会更加精简一点，以博客的方式来进行总结，思维导图和论文原文见[我的github](https://github.com/bsauce/Some-Papers-About-Fuzzing)。

最近开始有人关注我的总结，索性我就将之前看的论文都整理一下放上来。其实本文在github上已经半年没有更新了，主要是精力有限，没有时间去读那么多的论文，真心希望有志同道合、愿意分享的朋友和我一起来整理四大安全顶会的论文，最好是做成CTF WIKI那种东西，方便所有人一起阅读，有感兴趣的师傅可以联系我，我们在github上弄一个总结。分类方法是按专题和会议类型，内容是对论文的简短总结和xmind思维导图。

有感兴趣的师傅可以联系我啊！！！

简书网址：<https://www.jianshu.com/u/a12c5b882be2>

先知：<https://xz.aliyun.com/u/20655>

#  一、灰盒测试

###  0. fuzz综述—Fuzzing：State of the Art

看完综述，感觉还有好多文章值得看看，如下。

##### （1）fuzz类：

SAGE[14]

目标：windows x86大型读文件应用（如文件解析器，视频播放器，图片处理器）。
原理：concolic execution+启发式搜索算法。

Buzzfuzz[46]

首先插桩，然后污点分析，得到影响“攻击点”（如库调用）的输入中的变异位置，接着变异相应位置来生成新的测试用例，最后执行测试用例观察是否崩溃。

TaintScope[36/62]

针对checksum采用污点分析+预定义规则，检测checksum点和热输入字节（能污染目标程序的API），然后变异热字节并修改checksum点以通过完整性校验，最后利用SE+约束求解来修复测试用例的校验值，并使程序崩溃。

##### （2）内核fuzz

Trinity[32]

Syzkaller[15]

IOCTL Fuzzer[148]

KernelAFL（kAFL）[149]

CAB-Fuzz[150]

##### （3）程序分析技术—基础

污点分析-[105]

符号执行-[39]

### 1.VUzzer Application-aware Evolutionary Fuzzing-ndss2017

**总体**：VUzzer—开源，二进制文件（不需源码），灰盒-基于代码覆盖-基于变异，充分利用程序特性（DF/CF）来优化变异，利用控制流指定路径优先级：识别error-handling块，深路优先，常路滞后；利用数据流特性（DTA分析）可确定变异哪些字节+如何变异？两个亮点：一是路径权重计算，二是magic bytes策略。

**基于**：动态污点分析基于DataTracker，插桩基于Pin，静态分析基于IDA脚本。
轻型的程序分析

**具体**：改进AFL的反馈循环，给interesting路径更大的权重，亮点一在于路径权重的计算。基于Markov模型，块之间转移概率独立，即基本块的概率只和相连块有关，概率的倒数就是块权重，error-handling块权重为负值，路径上各块权重之和（取对数）即为路径权重，权重越大的路径对应的输入在下一轮变异中优先级越高。缺点是error-handling块的识别依赖种子输入的质量，数量要多且不会走error-handling块。亮点二是通过Pin插桩识别magic bytes（DTA分析），在cmp/lea处插桩，解决where/what问题。

**缺点**：error-handling代码寻找极度依赖种子输入的有效性；若某字节被多个输入字节所影响，而不是连续的magic bytes，则magic bytes失效；不适用于菜单式程序或交互式程序。

### 2-AFLFast_Coverage-based Greybox Fuzzing as Markov Chain-CCS2016

**简介**：AFLFast—开源，灰盒fuzzing，基于AFL。目标：AFL花大量时间执行高频路径，改进AFL，使其更多的fuzz低频路径。只能提高效率，而不能提高效果。改进AFL的ChooseNext()和AssignEnergy()函数，ChooseNext()（搜索策略）优先选择较少被选择的或低频路径的输入，变异次数由能量决定，能量调度策略是，被选次数更多的和被执行次数较少的（低频路径）能量较高。

##### 可了解的工具：

QEMU-运行时插桩

AFLDynInst [20]-将listing 1代码直接插入二进制文件。

[20] Tool. A binary instrumentation. https://github.com/vrtadmin/moow/tree/master/a-dyninst. Accessed:2016-05-13.


Markov链规律：状态之间的转换概率tp只取决于当前状态，而不是当前状态的路径。只能提高效率，而不能提高效果。

### 3-CollAFL：Path Sensitive Fuzzing-SP-2018

**简介**：亮点是解决hash碰撞问题并保持较低插桩开销，提出3种种子选取策略。

```c
cur_location = <COMPILE_TIME_RANDOM>;
shared_mem[cur_location ^ prev_location]++; 
prev_location = cur_location >> 1;
```

（1）解决hash碰撞问题（对于多前驱中的无碰撞块，Fmul(cur,prev)=(cur>>x)^(prev>>y)+z；对于多前驱中的碰撞块，Fhash(cur,prev)=hash_table_lookup(cur,prev)采用离线查表的方式；对于单前驱块，hash值可任意指定，硬编码。），采用贪心搜索确定最优xyz的值，若不能解决碰撞，可将bitmap大小扩充至128K。

（2）种子选取策略，路径上未探索相邻分支数、未探索孙子数、内存访问操作数大的优先变异，前两种策略效果最好。

afl-collect和AddressSanitizer[32]（检测缓冲区溢出和UAF）可以对crash进行去重。

**未来方向**：结合AdressSanitizer，检测非crash漏洞；现在依赖源码，未来在二进制程序上插桩。

### 4-Angora：Efficient Fuzzing by principled Search

Angora开源，亮点是用梯度下降方法（机器学习）求解约束条件，而不用符号执行的求解器。

**简介**：Angora属于灰盒fuzzing（需要源码），有五点创新：采用上下文敏感的分支计数，对同一函数的不同调用算作不同分支，增大代码覆盖率；采用字节级污点追踪，只变异影响路径走向的字节，树结构存储污点标记；变异方法是基于梯度下降方法（将判断条件转化为f(x)相关的函数），走未探索分支；有长度和类型推断技术，长度根据输入字节数与1248匹配，类型是根据指令的操作类型；输入长度探索是根据插桩确定，若read返回值参与条件判断，可适当调整输入字节。

**基于工具**：插桩-LLVMPass；污点追踪-DataFlowSanitizer

### 5.Steelix：Program-State Based Binary Fuzzing-FSE 2017

**简介**：Steelix—开源，针对binary，基于AFL 2.33b，基于灰盒变异fuzzing，基于代码覆盖。动态插桩是基于Dyninst，静态分析基于IDAPython。 

为什么感觉都是在模仿VUzzer？

目标是解决magic bytes比较问题，使用轻量级的静态分析收集interesting的比较（test/cmp/strcmp），利用二进制插桩获取运行时的比较值、生成运行时的比较进展信息（若匹配到1字节，相邻字节穷举变异的启发式策略）。缺点是不适用于不连续magic bytes和函数返回值比较（如hash值计算）。

### 6-AFLGo-Directed Greybox Fuzzing-CCS2017

**引申学习**：学LLVM，Adressanitizer

**简介**：AFLGo—开源，导向型灰盒fuzzing，给距离目标近的种子更多能量，亮点是如何求种子到多个目标的距离。缺点是需要外界输入目标，需要C源码。基于AFL实现

### 7-Hawkeye-Towards a Desired Directed Grey-box Fuzzer-CCS2018

**简介**：导向性灰盒fuzzer，需要源码+目标点，主要优化了AFLGo（不仅考虑短路径，也考虑能够到达目标点的长路径）。插桩基于LLVM，fuzz基于AFL，指针分析基于程间静态数据流分析工具SVF[41]。

**创新点**：3个亮点，1是权衡短路径与长路径的能量分配，覆盖期望集（所有能到达目标点的函数集）上更多函数的种子优先变异，路径越长重合越多，分数越高；2是适应性变异策略，若seed到达目标，细粒度变异增大，粗粒度变异下降；3是新种子优先级排序，分3层存储，若为新种子，且发现新边、能量较高、可到达目标点，则放第1层，否则放第2层，不为新种子则放第3层。

**未来工作**：实现binary fuzzing，目标识别基于二进制代码匹配[947]，静态分析基于IDA[20]，插桩基于Intel Pin[1]。


提出4个导向型fuzzer的特性并进行改进：考虑所有到达目标点的路径，不管长短；平衡静态分析的开销和实用性；合理分配能量；适应性变异策略。

### 8.Evaluating Fuzz Testing-2018

**简介**：调查32篇fuzz论文，研究如何设计fuzz实验才能得到可靠结果。

a. 选取基准算法

b. 选取测试目标程序

c. 选取评测标准——发现bug数

d. 确定算法参数——seed选取、time(24h)

e. 多次测试-30次取平均

##### Crash去重方法

（1）Ground Truth：找到的bug数目

​	修补对应bug，看其他输入还能否触发crash，以确保唯一性

（2）AFL Coverage Profile

​	若边覆盖（路径）唯一，就判定该crash“unique”

（3）Stack hashes

​	根据N层递归调用来区别漏洞。N：3-5，可快速比对漏洞

---

# 二、内核fuzz

### 1.DIFUZE- Interface Aware Fuzzing for Kernel Drivers-CCS-2017

**简介**：DIFUZE—开源，需要源码，接口感知型fuzzing—自动静态分析（先编译成LLVM中间码）驱动号（Range Analyziz[52]收集有效驱动号）、驱动文件名、输入参数的结构，已整合到Syzkaller。流程：分析内核源码，收集接口信息（如有效ioctl号、参数结构类型，采用LLVM 3.8实现），然后合成这些结构信息，发送给目标设备。缺点：依赖内核源码

**缺点**：

a. 早期就崩了，reboot，导致不能触发更深的功能。

b. 不能收集结构的复杂关系，eg，结构的length区域决定了某缓冲区的size。

**未来工作**：加上覆盖引导。

**想法**：VEX中间代码分析windows驱动？

##### interface recovery主要包含以下步骤：

（1）使用GCC及LLVM编译kernel，用于静态分析。

（2）识别驱动为处理交互创建的ioctl_handler函数。

（3）在ioctl_handler函数中分析出设备名信息。

（4）使用Range Analysis搜索判等表达式识别出command常量。

（5）追踪接受了用户态参数的copy_from_user等方法，找到command可以对应的结构体名称，为所有command建立结构体对应表。

（6）搜索整个kernel代码找到所有有效结构体的定义，并转换格式，记录在xml中。

（7）通过interface recovery后，作者能够利用这样有效的信息去生成有效合理的输入。

### 2.kAFL- Hardware-Assisted Feedback Fuzzing for OS Kernels-USENIX-2017

**简介**：kAFL—开源，无需源码，windows/linux/MacOS通用，基于AFL、VT-x、PT-Trace。基于硬件辅助反馈方式来fuzz闭源内核。

**利用两个硬件特性**：VT-x虚拟化技术；PT-Trace追踪功能。第一种是用于提高虚拟化效率的技术，相较于传统的模拟化，这种虚拟化使得VMM操作和控制VM时，将更加快速、可靠和安全。第二种PT追踪技术，让CPU可以搜集指令运行的部分上下文信息，这些信息对于推测Fuzz输入来说十分重要。将这两种技术与AFL相结合，实现kAFL。漏洞发现能力和效率都不错，附加开销很小（小于 5%）。

VMM中可以分为3个模块KVM，QEMU-PT和kAFL。VM又能分为Target Kernel和Agent。见Fig1-kAFL总体架构。

- KVM中实现了PT追踪功能，负责收集目标内核的运行信息。

- QEMU-PT除了作为KVM和kAFL交互的中间件之外，还有一个很重要的功能就是作为PT data的decoder。

- kAFL就是Fuzz工具的逻辑部分了，整体设计实现上都借鉴了AFL的思路。会根据反馈结果更高效的生成下一次输入。
- Target Kernel就是目标Kernel了，该工具对主流的操作系统都做了支持。

- Agent同样也作为一个交互的中间件，主要和目标Kernel做一些交互操作，如挂载镜像。

### 3. Digtool- A Virtualization-Based Framework for Detecting Kernel Vulnerabilities-usenix-2017

**目标**：不需源码，检测Windows内核漏洞。挖掘UNPROBE、TOCTTOU、UAF、OOB、参数未检查、信息泄漏六种漏洞识别，并且很快将支持第七种未初始化堆栈。

**总结**：亮点是没有用任何现有虚拟机或仿真器软件方案，独立实现了一套专用于内存监控的轻量级hypervisor。Digtool分为三个部分，一是hypervisor组件，初始化hypervisor并加载OS到VM，使用影子页表SPT监视指定线程的syscall的参数以及指定内存的使用；二是内核空间组件，设置需要监视的内存空间和syscall，拦截特定syscall后交给hypervisor处理（触发特定的行为事件），并把syscall信息记录到用户级log文件；三是用户空间组件，loader加载目标进程，通过配置文件指定监视的syscall和内存的区域，fuzzer负责发现分支和路径探索，log analyzer负责分析log文件检测UNPROBE/TOCTTOU漏洞。

采用硬件虚拟化，参考Intel开发者手册[23]。

**检测漏洞方法**：

UNPROBE—检测内核使用用户传递的指针时，是否检查它是否指向用户空间；TOCTTOU—两次访问同一内存->两次访问位于同一syscall中，这样会漏报/误报；UAF—hook内存分配/释放函数跟踪释放的内存页，直到它们被再次分配，任何对释放内存的访问都将被标记为 UAF 漏洞；OOB—Hook 分配/释放内存的函数，用AVL 树记录分配的内存空间，发生内存访问时则搜索AVL树，若找不到则发生OOB漏洞。

**实验结果**：速度比Bochspwn快，发现windows和第三方驱动的45个0day（其中41个杀软驱动漏洞，4个windows驱动漏洞）。

**Digtool 的局限**：

a.尽管其比仿真器快，但监视线程的性能开销仍然很高，性能开销主要来自 Hypervisor 和 Guest 操作系统之间的频繁切换。

b.目前仅支持 Windows 系统，Hypervisor 在 Guest 操作系统外运行，所以修改中间组件即可支持各种平台。

c.可以扩展检测算法来检测其他类型的漏洞，如竞争条件。

**工具总结**：

内核监视工具hypervisor：Xen；KVM。

二进制插桩工具：Pin[27]、DynamoTIO[13]、Valgrind[31]—用户级。

虚拟化工具：QEMU[11]\PEMU[42]—性能低。

---

# 三、程序分析技术

### 1.AddressSanitizer：A Fast Address Sanity Checker-USENIX-2012

AddressSanitizer:源码插桩，已整合到LLVM 3.1。（http://clang.llvm.org/docs/AddressSanitizer.html）。通过在用户内存（栈变量、全局变量、堆块）周围插入redzones，通过影子内存（1字节影子内存记录8字节用户空间，0表示都可访问，1-7表示前7字节可访问，负数表示不可访问）的记录来检查是否越界和UAF，堆检测是通过替换malloc和free函数。

##### ASAN组成：

a.插桩模块：在load/store处检查影子状态shadow state以检测越界访问；在栈/全局对象周围创建毒区poisoned redzones（>=2^3字节，以检测栈/全局变量的上溢和下溢）。

```c
ShadowAddr = (Addr >> 3) + Offset;
k = *ShadowAddr;
if (k != 0 && ((Addr & 7) + AccessSize > k))
	ReportAndCrash(Addr);
```

b.运行库：替换malloc/free及相关函数，在堆块周围创建毒区redzone(>=32字节，检测堆溢出)，延迟释放块的再使用（检测UAF），错误报告。

**缺点**：信息泄露漏洞不能立即被发现，也即未初始化读漏洞。

**改进想法**：释放后标记为不可读写，若再次申请到刚释放的块，仍保持为不可读，只有写入后才能读。

**不足**：未初始化读漏洞；未对齐越界访问漏洞；超长越界访问（redzone太小）。

**对比工具**：Valgrind[21]/Dr.Memory[8]速度减慢20x至10x，能检测未初始化读和内存泄露，不能检测栈、全局变量越界访问。

### 2.All You Ever Wanted to Know About DTA and SE-Oakland-2010

**简介**：主要内容是采用SimpIL语言统一描述DTA和SE过程，并描述其中的挑战。DTA的主要挑战是地址也被污染，控制流被污染，去掉不必要的污染，检测被攻击的时机；SE的挑战是符号化内存地址（别名分析），执行路径选择，符号化的跳转地址（如jump tables），处理系统/库调用，优化性能，部分变量符号化mixed execution。	

DTA和SE主要用于未知漏洞检测；自动输入筛选器生成（入侵检测）；恶意软件分析；测试样例生成。

### 3. S2E：A platform for in-vivo multi-path analysis of software systems

基于QEMU虚拟机[4]；KLEE符号执行引擎[11]；LLVM工具链[25]。

**简介**：本文提出S2E，能分析软件系统的特性和行为，可用于逆向工程、漏洞挖掘（内核或用户程序），能分析实际系统如windows。S2E基于两种技术，一是选择符号执行，可选择感兴趣的部分代码进行符号执行，二是松弛一致性模型，在复杂分析中权衡性能与准确性。S2E具备三种能力，一是能同时分析所有路径，二是能在真实软件栈（用户程序、库、内核、驱动等）中进行in-vivo分析（可以与环境交互，如读/写文件、发送/接收数据包），而不需要使用抽象模型，三是能直接分析二进制程序，所以可分析闭源软件。

**缺点**
（1）动态翻译的

S2E [16]和Revnic [14]提出了使用动态QEMU转换x86到LLVM的方法。与我们的方法不同，这些方法将代码块转换为LLVM，从而将LLVM 分析的应用程序一次仅限制到一个块。

（2）IR不全

Revnic [14]和RevGen [15]通过合并所述翻译块恢复的IR，但所回收的IR是不完整的，只适用于当前执行；因此，各种全程序分析将提供不完整的信息。

（3）没有抽象栈或促进信息

另外，翻译的代码保留了原始二进制有关堆栈布局的所??有的假设。他们不提供任何方法来获得抽象堆栈或将存储器位置升级为符号，这些符号对于应用几个源级分析是必不可少的。

**对比KLEE**：KLEE—基于LLVM编译器；S2E—基于QEMU，能进行全系统符号执行，支持在真实软件（用户程序、库、内核、驱动）栈中进行in-vivo分析而不需要使用抽象模型，支持选择符号执行能提高效率。所以选择S2E。

### 4. SVF：Interprocedural Static Value-Flow Analysis in LLVM

**资料**：

主页：http://svf-tools.github.io/SVF/

github主页：https://github.com/SVF-tools/SVF

环境搭建：https://github.com/SVF-tools/SVF/wiki/Setup-Guide-(CMake)

**SVF设计**：

svf框架是基于LLVM所写的，首先用clang将程序源码编译成bit code文件，然后使用LLVM Gold插件把bitcode文件整合到一个bc文件；指针分析——接着进行过程间的指针分析来生成指向信息；数值流构建——基于指向信息，构建内存SSA形式，这样就能识别顶层和地址变量的def-use关系链；应用——生成的数值流信息可用于检测数据泄露和空指针引用，也可以提高数值流分析和指针分析的精确度。

指针分析：指针分析的实现分为三个组件，分别是Graph,Rules和Solver。Graph从LLVM IR搜集抽象信息，确定对哪一部分进行指针分析；Rules定义了如何从语句中获得指向信息，例如graph中的约束；Solver确定约束的处理顺序。SVF提供了一个简洁可复用的接口，用户可以随意组合这三个组件来实现自己的指针分析。

数值流构建：基于获得的指向信息，我们实现了一个轻型的Mod-Ref Analysis，以寻找每个变量的过程间引用和被修改的副作用。给定Mod-Ref结果和指向信息，每个store/load/callsite的间接使用和定义都使用别名进行注释，每个别名都表示一组可以间接访问的抽象内存对象。注意，Open64和GCC都采用过程内的内存SSA，它是在过程内计算的，所有非局部变量都在一个单独的别名集中；相反，SVF提供了Mem Region Partitioning内存区域划分模块，允许用户定义自己的内存区域划分策略，以影响别名集的形成方式，这样在分析大型程序时可灵活地权衡可扩展性和精度。（总之，优点是能够划分模块进行分析）。

这样每个语句s（store/load/callsite）处的间接定义/使用的别名记作Ds/Us，

稀疏VFG表示：稀疏VFG是一个导向图，包含所有变量的def-use关系。

**应用场景**：

1. Source-Sink Analysis: 如检测内存泄露漏洞，检查内存分配是否最终走到释放点，给定顶层和地址变量的数值流，SABER[36,37]/SPARROW[24]能检测到泄露漏洞，通过SVF框架还能检测double-free、文件open-close错误、污点数据使用错误。

2. 指针分析: 能提高指针分析的可扩展性和准确性，例如SELFS[44]，能基于数值流信息对部分程序区域实施选择流敏感指针分析；FSAM[34]是基于SVF的，能对多线程c程序进行线程交错分析，以进行稀疏流敏感指针分析。

3. 加速动态分析：动态分析，通过插桩监视程序执行行为，带来了运行时的开销。可以采用静态数值流信息来引导实施选择性插桩，这样就能消除一些不必要的插桩，降低运行开销。例如USHER[43]使用过程间数值流分析来识别多余的操作，移除该处的插桩，还能用于检测其他漏洞如空指针引用和缓冲区溢出[42];还可以与符号执行[10]和动态数据流测试[16]相结合，以更快生成更有意义的测试用例。

4. 程序调试与理解：SVF还能用于软件调试和程序理解[18,21,40]，可以通过只追踪相关的数值流来寻找引发错误行为的语句，不必分析不相关的语句；可扩展和精确的过程间数值流分析也对软件可视化有帮助（code map[20])。

---

# 五、并行fuzz

没有读过，就只放上相关的工具和论文。详细总结点[这里](https://mp.weixin.qq.com/s/wjp-54oevmK4XNAuEi_AnA)。

**1.并行符号化执行**——[Cloud9](http://cloud9.epfl.ch/)

**2.并行黑盒模糊测试**——《Using Grid Computing for Large Scale Fuzzing》

**3.并行灰盒模糊测试**——[**OSS-fuzz**](https://github.com/google/oss-fuzz)、[**ClusterFuzz**](https://github.com/google/clusterfuzz)、[**Springfield**](https://devblogs.microsoft.com/dotnet/project-springfield-a-cloud-service-built-entirely-in-f/)

PAFL: Extend FuzzingOptimizations of Single Mode to Industrial Parallel Mode——FSE2018

EnFuzz: Ensemble Fuzzing withSeed Synchronization among Diverse Fuzzers——USENIX2019

FOT: a versatile,configurable, extensible fuzzing framework——FSE2018

---

有感兴趣的师傅可以联系我啊！！！一起来总结啊！！！
