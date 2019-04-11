## Some papers about fuzzing

​	分享一下读过的最新的fuzzing论文，目前是用Xmind记录的，可能过于详细了些，未来会更加精简一点，以博客的方式来进行总结。

​	简书网址：https://www.jianshu.com/u/a12c5b882be2

​	github网址：https://github.com/bsauce/Some-Papers-About-Fuzzing

#灰盒测试

###0-fuzz综述—Fuzzing：State of the Art

​	看完综述，感觉还有好多文章值得看看，如下。

#####fuzz类：

SAGE[14]
目标：windows x86大型读文件应用（如文件解析器，视频播放器，图片处理器）。
原理：concolic execution+启发式搜索算法。

Buzzfuzz[46]
首先插桩，然后污点分析，得到影响“攻击点”（如库调用）的输入中的变异位置，接着变异相应位置来生成新的测试用例，最后执行测试用例观察是否崩溃。

TaintScope[36][62]
针对checksum采用污点分析+预定义规则，检测checksum点和热输入字节（能污染目标程序的API），然后变异热字节并修改checksum点以通过完整性校验，最后利用SE+约束求解来修复测试用例的校验值，并使程序崩溃。

#####内核fuzz

Trinity[32]
Syzkaller[15]
IOCTL Fuzzer[148]
KernelAFL（kAFL）[149]
CAB-Fuzz[150]

#####程序分析技术—基础

污点分析-[105]
符号执行-[39]

###1.VUzzer Application-aware Evolutionary Fuzzing-ndss2017

总体：VUzzer—开源，二进制文件（不需源码），灰盒-基于代码覆盖-基于变异，充分利用程序特性（DF/CF）来优化变异，利用控制流指定路径优先级：识别error-handling块，深路优先，常路滞后；利用数据流特性（DTA分析）可确定变异哪些字节+如何变异？两个亮点：一是路径权重计算，二是magic bytes策略。

基于：动态污点分析基于DataTracker，插桩基于Pin，静态分析基于IDA脚本。
轻型的程序分析

具体：改进AFL的反馈循环，给interesting路径更大的权重，亮点一在于路径权重的计算。基于Markov模型，块之间转移概率独立，即基本块的概率只和相连块有关，概率的倒数就是块权重，error-handling块权重为负值，路径上各块权重之和（取对数）即为路径权重，权重越大的路径对应的输入在下一轮变异中优先级越高。缺点是error-handling块的识别依赖种子输入的质量，数量要多且不会走error-handling块。亮点二是通过Pin插桩识别magic bytes（DTA分析），在cmp/lea处插桩，解决where/what问题。

缺点：error-handling代码寻找极度依赖种子输入的有效性；若某字节被多个输入字节所影响，而不是连续的magic bytes，则magic bytes失效；不适用于菜单式程序或交互式程序。

###2-AFLFast_Coverage-based Greybox Fuzzing as Markov Chain-CCS2016

AFLFast—开源，灰盒fuzzing，基于AFL。目标：AFL花大量时间执行高频路径，改进AFL，使其更多的fuzz低频路径。只能提高效率，而不能提高效果。改进AFL的ChooseNext()和AssignEnergy()函数，ChooseNext()（搜索策略）优先选择较少被选择的或低频路径的输入，变异次数由能量决定，能量调度策略是，被选次数更多的和被执行次数较少的（低频路径）能量较高。

#####可了解的工具：

QEMU-运行时插桩
AFLDynInst [20]-将listing 1代码直接插入二进制文件。
	[20] Tool. A binary instrumentation. https://github.com/vrtadmin/moow/tree/master/a-dyninst. Accessed:2016-05-13.


Markov链规律：状态之间的转换概率tp只取决于当前状态，而不是当前状态的路径。只能提高效率，而不能提高效果。

###3-CollAFL：Path Sensitive Fuzzing-SP-2018

亮点是解决hash碰撞问题并保持较低插桩开销，提出3种种子选取策略。


  cur_location = <COMPILE_TIME_RANDOM>;
  shared_mem[cur_location ^ prev_location]++; 
  prev_location = cur_location >> 1;

（1）解决hash碰撞问题（对于多前驱中的无碰撞块，Fmul(cur,prev)=(cur>>x)^(prev>>y)+z；对于多前驱中的碰撞块，Fhash(cur,prev)=hash_table_lookup(cur,prev)采用离线查表的方式；对于单前驱块，hash值可任意指定，硬编码。），采用贪心搜索确定最优xyz的值，若不能解决碰撞，可将bitmap大小扩充至128K。
（2）种子选取策略，路径上未探索相邻分支数、未探索孙子数、内存访问操作数大的优先变异，前两种策略效果最好。

afl-collect和AddressSanitizer[32]（检测缓冲区溢出和UAF）可以对crash进行去重。


未来方向：结合AdressSanitizer，检测非crash漏洞；现在依赖源码，未来在二进制程序上插桩。

###4-Angora：Efficient Fuzzing by principled Search

​         Angora开源，亮点是用梯度下降方法（机器学习）求解约束条件，而不用符号执行的求解器

​         Angora属于灰盒fuzzing（需要源码），有四点创新：采用上下文敏感的分支计数，对同一函数的不同调用算作不同分支，增大代码覆盖率；采用字节级污点追踪，只变异影响路径走向的字节，树结构存储污点标记；变异方法是基于梯度下降方法（将判断条件转化为f(x)相关的函数），走未探索分支；有长度和类型推断技术，长度根据输入字节数与1248匹配，类型是根据指令的操作类型；输入长度探索是根据插桩确定，若read返回值参与条件判断，可适当调整输入字节。

​         基于工具：插桩-LLVMPass；污点追踪-DataFlowSanitizer

###5.Steelix：Program-State Based Binary Fuzzing-FSE 2017

​	Steelix—开源，针对binary，基于AFL 2.33b，基于灰盒变异fuzzing，基于代码覆盖。动态插桩是基于Dyninst，静态分析基于IDAPython。
	模仿VUzzer。
	目标是解决magic bytes比较问题，使用轻量级的静态分析收集interesting的比较（test/cmp/strcmp），利用二进制插桩获取运行时的比较值、生成运行时的比较进展信息（若匹配到1字节，相邻字节穷举变异的启发式策略）。缺点是不适用于不连续magic bytes和函数返回值比较（如hash值计算）。

###6-AFLGo-Directed Greybox Fuzzing-CCS2017

引申学习：学LLVM，Adressanitizer

AFLGo——开源，导向型灰盒fuzzing，给距离目标近的种子更多能量，亮点是如何求种子到多个目标的距离。缺点是需要外界输入目标，需要C源码。基于AFL实现

###7-Hawkeye-Towards a Desired Directed Grey-box Fuzzer-CCS2018

​	导向性灰盒fuzzer，需要源码+目标点，主要优化了AFLGo（不仅考虑短路径，也考虑能够到达目标点的长路径）。插桩基于LLVM，fuzz基于AFL，指针分析基于程间静态数据流分析工具SVF[41]。
	3个亮点，1是权衡短路径与长路径的能量分配，覆盖期望集（所有能到达目标点的函数集）上更多函数的种子优先变异，路径越长重合越多，分数越高；2是适应性变异策略，若seed到达目标，细粒度变异增大，粗粒度变异下降；3是新种子优先级排序，分3层存储，若为新种子，且发现新边、能量较高、可到达目标点，则放第1层，否则放第2层，不为新种子则放第3层。
	未来工作是实现binary fuzzing，目标识别基于二进制代码匹配[947]，静态分析基于IDA[20]，插桩基于Intel Pin[1]。


​	提出4个导向型fuzzer的特性并进行改进：考虑所有到达目标点的路径，不管长短；平衡静态分析的开销和实用性；合理分配能量；适应性变异策略。

###8.Evaluating Fuzz Testing-2018

​	调查32篇fuzz论文，研究如何设计fuzz实验才能得到可靠结果。

​	a. 选取基准算法

​	b. 选取测试目标程序

​	c. 选取评测标准——发现bug数

​	d. 确定算法参数——seed选取、time(24h)

​	e. 多次测试-30次取平均

#####Crash去重方法

（1）Ground Truth：找到的bug数目

​	修补对应bug，看其他输入还能否触发crash，以确保唯一性

（2）AFL Coverage Profile

​	若边覆盖（路径）唯一，就判定该crash“unique”

（3）Stack hashes

​	根据N层递归调用来区别漏洞。N：3-5，可快速比对漏洞

#内核fuzz

###1.DIFUZE- Interface Aware Fuzzing for Kernel Drivers-CCS-2017

DIFUZE—开源，需要源码，接口感知型fuzzing—自动静态分析（先编译成LLVM中间码）驱动号（Range Analyziz[52]收集有效驱动号）、驱动文件名、输入参数的结构，已整合到Syzkaller。流程：分析内核源码，收集接口信息（如有效ioctl号、参数结构类型，采用LLVM 3.8实现），然后合成这些结构信息，发送给目标设备。缺点：依赖内核源码

缺点：

​	a. 早期就崩了，reboot，导致不能触发更深的功能。
	b. 不能收集结构的复杂关系，eg，结构的length区域决定了某缓冲区的size。

未来工作：加上覆盖引导。
想法：VEX中间代码分析windows驱动？

#####interface recovery主要包含以下步骤：


（1）使用GCC及LLVM编译kernel，用于静态分析。
（2）
识别驱动为处理交互创建的ioctl_handler函数。

（3）在ioctl_handler函数中分析出设备名信息。
（4）使用Range Analysis搜索判等表达式识别出command常量。
（5）追踪接受了用户态参数的copy_from_user等方法，找到command可以对应的结构体名称，为所有command建立结构体对应表。
（6）搜索整个kernel代码找到所有有效结构体的定义，并转换格式，记录在xml中。

（7）通过interface recovery后，作者能够利用这样有效的信息去生成有效合理的输入。

###2.kAFL- Hardware-Assisted Feedback Fuzzing for OS Kernels-USENIX-2017

kAFL—开源，无需源码，windows/linux/MacOS通用，基于AFL、VT-x、PT-Trace。基于硬件辅助反馈方式来fuzz闭源内核。
	利用两个硬件特性：VT-x虚拟化技术；PT-Trace追踪功能。第一种是用于提高虚拟化效率的技术，相较于传统的模拟化，这种虚拟化使得VMM操作和控制VM时，将更加快速、可靠和安全。第二种PT追踪技术，让CPU可以搜集指令运行的部分上下文信息，这些信息对于推测Fuzz输入来说十分重要。将这两种技术与AFL相结合，实现kAFL。漏洞发现能力和效率都不错，附加开销很小（小于 5%）。


VMM中可以分为3个模块KVM，QEMU-PT和kAFL。VM又能分为Target Kernel和Agent。见Fig1-kAFL总体架构。
	-KVM中实现了PT追踪功能，负责收集目标内核的运行信息。

​	-QEMU-PT除了作为KVM和kAFL交互的中间件之外，还有一个很重要的功能就是作为PT data的decoder。

​	-kAFL就是Fuzz工具的逻辑部分了，整体设计实现上都借鉴了AFL的思路。会根据反馈结果更高效的生成下一次输入。
	-Target Kernel就是目标Kernel了，该工具对主流的操作系统都做了支持。

​	-Agent同样也作为一个交互的中间件，主要和目标Kernel做一些交互操作，如挂载镜像。

###3.Razzer：Finding Kernel Race Bugs through Fuzzing-SP-2019

​	静态分析确定可疑竞争代码，动态fuzz测试分两个阶段，一是单线程fuzz测试（找到能执行两条竞争指令的输入程序），二是多线程fuzz测试（通过监管器在竞争指令处断点，确定性的线程交错技术，控制线程调度，提供准确的并行执行信息）。输出详细分析report，竞争点—2个内存访问指令的地址+调用栈信息。
	静态分析基于LLVM pass分析中间码bitcode，SVF指针分析[39]，K-miner[17]；监管器基于QEMU [5]+KVM（kernel-based Virtual Machine硬件加速）。

缺点：没有解决同步机制对多线程fuzzing的影响。

#程序分析技术

###1.AddressSanitizer：A Fast Address Sanity Checker-USENIX-2012

AddressSanitizer:源码插桩，已整合到LLVM 3.1。（http://clang.llvm.org/docs/AddressSanitizer.html）。通过在用户内存（栈变量、全局变量、堆块）周围插入redzones，通过影子内存（1字节影子内存记录8字节用户空间，0表示都可访问，1-7表示前7字节可访问，负数表示不可访问）的记录来检查是否越界和UAF，堆检测是通过替换malloc和free函数。

#####ASAN组成：

​	a.插桩模块：在load/store处检查影子状态shadow state以检测越界访问；在栈/全局对象周围创建毒区poisoned redzones（>=2^3字节，以检测栈/全局变量的上溢和下溢）。
	ShadowAddr = (Addr >> 3) + Offset;
	k = *ShadowAddr;
	if (k != 0 && ((Addr & 7) + AccessSize > k))
		ReportAndCrash(Addr);
	b.运行库：替换malloc/free及相关函数，在堆块周围创建毒区redzone(>=32字节，检测堆溢出)，延迟释放块的再使用（检测UAF），错误报告。
	缺点：信息泄露漏洞不能立即被发现，也即未初始化读漏洞。
	改进想法：释放后标记为不可读写，若再次申请到刚释放的块，仍保持为不可读，只有写入后才能读。

#####不足：

​	未初始化读漏洞；未对齐越界访问漏洞；超长越界访问（redzone太小）。

#####对比工具：

​	Valgrind[21]/Dr.Memory[8]速度减慢20x至10x，能检测未初始化读和内存泄露，不能检测栈、全局变量越界访问。

###2.All You Ever Wanted to Know About DTA and SE-Oakland-2010

​	主要内容是采用SimpIL语言统一描述DTA和SE过程，并描述其中的挑战。DTA的主要挑战是地址也被污染，控制流被污染，去掉不必要的污染，检测被攻击的时机；SE的挑战是符号化内存地址（别名分析），执行路径选择，符号化的跳转地址（如jump tables），处理系统/库调用，优化性能，部分变量符号化mixed execution。DTA和SE主要用于未知漏洞检测；自动输入筛选器生成（入侵检测）；恶意软件分析；测试样例生成。





















