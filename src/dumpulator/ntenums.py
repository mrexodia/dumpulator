# Automatically generated with parse_phnt.py, do not edit
from enum import Enum

class EVENT_TYPE(Enum):
    NotificationEvent = 0
    SynchronizationEvent = 1

class TIMER_TYPE(Enum):
    NotificationTimer = 0
    SynchronizationTimer = 1

class WAIT_TYPE(Enum):
    WaitAll = 0
    WaitAny = 1
    WaitNotification = 2

class NT_PRODUCT_TYPE(Enum):
    NtProductWinNt = 1
    NtProductLanManNt = 2
    NtProductServer = 3

class SUITE_TYPE(Enum):
    SmallBusiness = 0
    Enterprise = 1
    BackOffice = 2
    CommunicationServer = 3
    TerminalServer = 4
    SmallBusinessRestricted = 5
    EmbeddedNT = 6
    DataCenter = 7
    SingleUserTS = 8
    Personal = 9
    Blade = 10
    EmbeddedRestricted = 11
    SecurityAppliance = 12
    StorageServer = 13
    ComputeServer = 14
    WHServer = 15
    PhoneNT = 16
    MaxSuiteType = 17

class KTHREAD_STATE(Enum):
    Initialized = 0
    Ready = 1
    Running = 2
    Standby = 3
    Terminated = 4
    Waiting = 5
    Transition = 6
    DeferredReady = 7
    GateWaitObsolete = 8
    WaitingForProcessInSwap = 9
    MaximumThreadState = 10

class KHETERO_CPU_POLICY(Enum):
    KHeteroCpuPolicyAll = 0
    KHeteroCpuPolicyLarge = 1
    KHeteroCpuPolicyLargeOrIdle = 2
    KHeteroCpuPolicySmall = 3
    KHeteroCpuPolicySmallOrIdle = 4
    KHeteroCpuPolicyDynamic = 5
    KHeteroCpuPolicyStaticMax = 5  # valid
    KHeteroCpuPolicyBiasedSmall = 6
    KHeteroCpuPolicyBiasedLarge = 7
    KHeteroCpuPolicyDefault = 8
    KHeteroCpuPolicyMax = 9

class KWAIT_REASON(Enum):
    Executive = 0
    FreePage = 1
    PageIn = 2
    PoolAllocation = 3
    DelayExecution = 4
    Suspended = 5
    UserRequest = 6
    WrExecutive = 7
    WrFreePage = 8
    WrPageIn = 9
    WrPoolAllocation = 10
    WrDelayExecution = 11
    WrSuspended = 12
    WrUserRequest = 13
    WrEventPair = 14
    WrQueue = 15
    WrLpcReceive = 16
    WrLpcReply = 17
    WrVirtualMemory = 18
    WrPageOut = 19
    WrRendezvous = 20
    WrKeyedEvent = 21
    WrTerminated = 22
    WrProcessInSwap = 23
    WrCpuRateControl = 24
    WrCalloutStack = 25
    WrKernel = 26
    WrResource = 27
    WrPushLock = 28
    WrMutex = 29
    WrQuantumEnd = 30
    WrDispatchInt = 31
    WrPreempted = 32
    WrYieldExecution = 33
    WrFastMutex = 34
    WrGuardedMutex = 35
    WrRundown = 36
    WrAlertByThreadId = 37
    WrDeferredPreempt = 38
    WrPhysicalFault = 39
    WrIoRing = 40
    WrMdlCache = 41
    MaximumWaitReason = 42

class KPROFILE_SOURCE(Enum):
    ProfileTime = 0
    ProfileAlignmentFixup = 1
    ProfileTotalIssues = 2
    ProfilePipelineDry = 3
    ProfileLoadInstructions = 4
    ProfilePipelineFrozen = 5
    ProfileBranchInstructions = 6
    ProfileTotalNonissues = 7
    ProfileDcacheMisses = 8
    ProfileIcacheMisses = 9
    ProfileCacheMisses = 10
    ProfileBranchMispredictions = 11
    ProfileStoreInstructions = 12
    ProfileFpInstructions = 13
    ProfileIntegerInstructions = 14
    Profile2Issue = 15
    Profile3Issue = 16
    Profile4Issue = 17
    ProfileSpecialInstructions = 18
    ProfileTotalCycles = 19
    ProfileIcacheIssues = 20
    ProfileDcacheAccesses = 21
    ProfileMemoryBarrierCycles = 22
    ProfileLoadLinkedIssues = 23
    ProfileMaximum = 24

class LDR_DDAG_STATE(Enum):
    LdrModulesMerged = -5
    LdrModulesInitError = -4
    LdrModulesSnapError = -3
    LdrModulesUnloaded = -2
    LdrModulesUnloading = -1
    LdrModulesPlaceHolder = 0
    LdrModulesMapping = 1
    LdrModulesMapped = 2
    LdrModulesWaitingForDependencies = 3
    LdrModulesSnapping = 4
    LdrModulesSnapped = 5
    LdrModulesCondensed = 6
    LdrModulesReadyToInit = 7
    LdrModulesInitializing = 8
    LdrModulesReadyToRun = 9

class LDR_DLL_LOAD_REASON(Enum):
    LoadReasonStaticDependency = 0
    LoadReasonStaticForwarderDependency = 1
    LoadReasonDynamicForwarderDependency = 2
    LoadReasonDelayloadDependency = 3
    LoadReasonDynamicLoad = 4
    LoadReasonAsImageLoad = 5
    LoadReasonAsDataLoad = 6
    LoadReasonEnclavePrimary = 7  # since REDSTONE3
    LoadReasonEnclaveDependency = 8
    LoadReasonPatchImage = 9  # since WIN11
    LoadReasonUnknown = -1

class LDR_HOT_PATCH_STATE(Enum):
    LdrHotPatchBaseImage = 0
    LdrHotPatchNotApplied = 1
    LdrHotPatchAppliedReverse = 2
    LdrHotPatchAppliedForward = 3
    LdrHotPatchFailedToPatch = 4
    LdrHotPatchStateMax = 5

class SYSTEM_ENVIRONMENT_INFORMATION_CLASS(Enum):
    SystemEnvironmentNameInformation = 1  # q: VARIABLE_NAME
    SystemEnvironmentValueInformation = 2  # q: VARIABLE_NAME_AND_VALUE
    MaxSystemEnvironmentInfoClass = 3

class FILTER_BOOT_OPTION_OPERATION(Enum):
    FilterBootOptionOperationOpenSystemStore = 0
    FilterBootOptionOperationSetElement = 1
    FilterBootOptionOperationDeleteElement = 2
    FilterBootOptionOperationMax = 3

class EVENT_INFORMATION_CLASS(Enum):
    EventBasicInformation = 0

class MUTANT_INFORMATION_CLASS(Enum):
    MutantBasicInformation = 0  # MUTANT_BASIC_INFORMATION
    MutantOwnerInformation = 1  # MUTANT_OWNER_INFORMATION

class SEMAPHORE_INFORMATION_CLASS(Enum):
    SemaphoreBasicInformation = 0

class TIMER_INFORMATION_CLASS(Enum):
    TimerBasicInformation = 0  # TIMER_BASIC_INFORMATION

class TIMER_SET_INFORMATION_CLASS(Enum):
    TimerSetCoalescableTimer = 0  # TIMER_SET_COALESCABLE_TIMER_INFO
    MaxTimerInfoClass = 1

class WNF_STATE_NAME_LIFETIME(Enum):
    WnfWellKnownStateName = 0
    WnfPermanentStateName = 1
    WnfPersistentStateName = 2
    WnfTemporaryStateName = 3

class WNF_STATE_NAME_INFORMATION(Enum):
    WnfInfoStateNameExist = 0
    WnfInfoSubscribersPresent = 1
    WnfInfoIsQuiescent = 2

class WNF_DATA_SCOPE(Enum):
    WnfDataScopeSystem = 0
    WnfDataScopeSession = 1
    WnfDataScopeUser = 2
    WnfDataScopeProcess = 3
    WnfDataScopeMachine = 4  # REDSTONE3
    WnfDataScopePhysicalMachine = 5  # WIN11

class WORKERFACTORYINFOCLASS(Enum):
    WorkerFactoryTimeout = 0  # LARGE_INTEGER
    WorkerFactoryRetryTimeout = 1  # LARGE_INTEGER
    WorkerFactoryIdleTimeout = 2  # s: LARGE_INTEGER
    WorkerFactoryBindingCount = 3  # s: ULONG
    WorkerFactoryThreadMinimum = 4  # s: ULONG
    WorkerFactoryThreadMaximum = 5  # s: ULONG
    WorkerFactoryPaused = 6  # ULONG or BOOLEAN
    WorkerFactoryBasicInformation = 7  # q: WORKER_FACTORY_BASIC_INFORMATION
    WorkerFactoryAdjustThreadGoal = 8
    WorkerFactoryCallbackType = 9
    WorkerFactoryStackInformation = 10  # 10
    WorkerFactoryThreadBasePriority = 11  # s: ULONG
    WorkerFactoryTimeoutWaiters = 12  # s: ULONG, since THRESHOLD
    WorkerFactoryFlags = 13  # s: ULONG
    WorkerFactoryThreadSoftMaximum = 14  # s: ULONG
    WorkerFactoryThreadCpuSets = 15  # since REDSTONE5
    MaxWorkerFactoryInfoClass = 16

class SYSTEM_INFORMATION_CLASS(Enum):
    SystemBasicInformation = 0  # q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation = 1  # q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation = 2  # q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation = 3  # q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation = 4  # not implemented
    SystemProcessInformation = 5  # q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation = 6  # q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation = 7  # q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation = 8  # q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation = 9  # q: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation = 10  # not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
    SystemModuleInformation = 11  # q: RTL_PROCESS_MODULES
    SystemLocksInformation = 12  # q: RTL_PROCESS_LOCKS
    SystemStackTraceInformation = 13  # q: RTL_PROCESS_BACKTRACES
    SystemPagedPoolInformation = 14  # not implemented
    SystemNonPagedPoolInformation = 15  # not implemented
    SystemHandleInformation = 16  # q: SYSTEM_HANDLE_INFORMATION
    SystemObjectInformation = 17  # q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
    SystemPageFileInformation = 18  # q: SYSTEM_PAGEFILE_INFORMATION
    SystemVdmInstemulInformation = 19  # q: SYSTEM_VDM_INSTEMUL_INFO
    SystemVdmBopInformation = 20  # not implemented // 20
    SystemFileCacheInformation = 21  # q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
    SystemPoolTagInformation = 22  # q: SYSTEM_POOLTAG_INFORMATION
    SystemInterruptInformation = 23  # q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemDpcBehaviorInformation = 24  # q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
    SystemFullMemoryInformation = 25  # not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemLoadGdiDriverInformation = 26  # s (kernel-mode only)
    SystemUnloadGdiDriverInformation = 27  # s (kernel-mode only)
    SystemTimeAdjustmentInformation = 28  # q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
    SystemSummaryMemoryInformation = 29  # not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemMirrorMemoryInformation = 30  # s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
    SystemPerformanceTraceInformation = 31  # q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
    SystemObsolete0 = 32  # not implemented
    SystemExceptionInformation = 33  # q: SYSTEM_EXCEPTION_INFORMATION
    SystemCrashDumpStateInformation = 34  # s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
    SystemKernelDebuggerInformation = 35  # q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
    SystemContextSwitchInformation = 36  # q: SYSTEM_CONTEXT_SWITCH_INFORMATION
    SystemRegistryQuotaInformation = 37  # q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
    SystemExtendServiceTableInformation = 38  # s (requires SeLoadDriverPrivilege) // loads win32k only
    SystemPrioritySeperation = 39  # s (requires SeTcbPrivilege)
    SystemVerifierAddDriverInformation = 40  # s (requires SeDebugPrivilege) // 40
    SystemVerifierRemoveDriverInformation = 41  # s (requires SeDebugPrivilege)
    SystemProcessorIdleInformation = 42  # q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemLegacyDriverInformation = 43  # q: SYSTEM_LEGACY_DRIVER_INFORMATION
    SystemCurrentTimeZoneInformation = 44  # q; s: RTL_TIME_ZONE_INFORMATION
    SystemLookasideInformation = 45  # q: SYSTEM_LOOKASIDE_INFORMATION
    SystemTimeSlipNotification = 46  # s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
    SystemSessionCreate = 47  # not implemented
    SystemSessionDetach = 48  # not implemented
    SystemSessionInformation = 49  # not implemented (SYSTEM_SESSION_INFORMATION)
    SystemRangeStartInformation = 50  # q: SYSTEM_RANGE_START_INFORMATION // 50
    SystemVerifierInformation = 51  # q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
    SystemVerifierThunkExtend = 52  # s (kernel-mode only)
    SystemSessionProcessInformation = 53  # q: SYSTEM_SESSION_PROCESS_INFORMATION
    SystemLoadGdiDriverInSystemSpace = 54  # s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
    SystemNumaProcessorMap = 55  # q: SYSTEM_NUMA_INFORMATION
    SystemPrefetcherInformation = 56  # q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
    SystemExtendedProcessInformation = 57  # q: SYSTEM_PROCESS_INFORMATION
    SystemRecommendedSharedDataAlignment = 58  # q: ULONG // KeGetRecommendedSharedDataAlignment
    SystemComPlusPackage = 59  # q; s: ULONG
    SystemNumaAvailableMemory = 60  # q: SYSTEM_NUMA_INFORMATION // 60
    SystemProcessorPowerInformation = 61  # q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemEmulationBasicInformation = 62  # q: SYSTEM_BASIC_INFORMATION
    SystemEmulationProcessorInformation = 63  # q: SYSTEM_PROCESSOR_INFORMATION
    SystemExtendedHandleInformation = 64  # q: SYSTEM_HANDLE_INFORMATION_EX
    SystemLostDelayedWriteInformation = 65  # q: ULONG
    SystemBigPoolInformation = 66  # q: SYSTEM_BIGPOOL_INFORMATION
    SystemSessionPoolTagInformation = 67  # q: SYSTEM_SESSION_POOLTAG_INFORMATION
    SystemSessionMappedViewInformation = 68  # q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
    SystemHotpatchInformation = 69  # q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
    SystemObjectSecurityMode = 70  # q: ULONG // 70
    SystemWatchdogTimerHandler = 71  # s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
    SystemWatchdogTimerInformation = 72  # q: SYSTEM_WATCHDOG_TIMER_INFORMATION // (kernel-mode only)
    SystemLogicalProcessorInformation = 73  # q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemWow64SharedInformationObsolete = 74  # not implemented
    SystemRegisterFirmwareTableInformationHandler = 75  # s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
    SystemFirmwareTableInformation = 76  # SYSTEM_FIRMWARE_TABLE_INFORMATION
    SystemModuleInformationEx = 77  # q: RTL_PROCESS_MODULE_INFORMATION_EX
    SystemVerifierTriageInformation = 78  # not implemented
    SystemSuperfetchInformation = 79  # q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
    SystemMemoryListInformation = 80  # q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
    SystemFileCacheInformationEx = 81  # q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
    SystemThreadPriorityClientIdInformation = 82  # s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
    SystemProcessorIdleCycleTimeInformation = 83  # q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
    SystemVerifierCancellationInformation = 84  # SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
    SystemProcessorPowerInformationEx = 85  # not implemented
    SystemRefTraceInformation = 86  # q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
    SystemSpecialPoolInformation = 87  # q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
    SystemProcessIdInformation = 88  # q: SYSTEM_PROCESS_ID_INFORMATION
    SystemErrorPortInformation = 89  # s (requires SeTcbPrivilege)
    SystemBootEnvironmentInformation = 90  # q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
    SystemHypervisorInformation = 91  # q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
    SystemVerifierInformationEx = 92  # q; s: SYSTEM_VERIFIER_INFORMATION_EX
    SystemTimeZoneInformation = 93  # q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemImageFileExecutionOptionsInformation = 94  # s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
    SystemCoverageInformation = 95  # q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
    SystemPrefetchPatchInformation = 96  # SYSTEM_PREFETCH_PATCH_INFORMATION
    SystemVerifierFaultsInformation = 97  # s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
    SystemSystemPartitionInformation = 98  # q: SYSTEM_SYSTEM_PARTITION_INFORMATION
    SystemSystemDiskInformation = 99  # q: SYSTEM_SYSTEM_DISK_INFORMATION
    SystemProcessorPerformanceDistribution = 100  # q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // 100
    SystemNumaProximityNodeInformation = 101  # q; s: SYSTEM_NUMA_PROXIMITY_MAP
    SystemDynamicTimeZoneInformation = 102  # q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemCodeIntegrityInformation = 103  # q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
    SystemProcessorMicrocodeUpdateInformation = 104  # s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
    SystemProcessorBrandString = 105  # q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
    SystemVirtualAddressInformation = 106  # q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
    SystemLogicalProcessorAndGroupInformation = 107  # q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // KeQueryLogicalProcessorRelationship
    SystemProcessorCycleTimeInformation = 108  # q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
    SystemStoreInformation = 109  # q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
    SystemRegistryAppendString = 110  # s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
    SystemAitSamplingValue = 111  # s: ULONG (requires SeProfileSingleProcessPrivilege)
    SystemVhdBootInformation = 112  # q: SYSTEM_VHD_BOOT_INFORMATION
    SystemCpuQuotaInformation = 113  # q; s: PS_CPU_QUOTA_QUERY_INFORMATION
    SystemNativeBasicInformation = 114  # q: SYSTEM_BASIC_INFORMATION
    SystemErrorPortTimeouts = 115  # SYSTEM_ERROR_PORT_TIMEOUTS
    SystemLowPriorityIoInformation = 116  # q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
    SystemTpmBootEntropyInformation = 117  # q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
    SystemVerifierCountersInformation = 118  # q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
    SystemPagedPoolInformationEx = 119  # q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
    SystemSystemPtesInformationEx = 120  # q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
    SystemNodeDistanceInformation = 121  # q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber)
    SystemAcpiAuditInformation = 122  # q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
    SystemBasicPerformanceInformation = 123  # q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
    SystemQueryPerformanceCounterInformation = 124  # q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
    SystemSessionBigPoolInformation = 125  # q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
    SystemBootGraphicsInformation = 126  # q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
    SystemScrubPhysicalMemoryInformation = 127  # q; s: MEMORY_SCRUB_INFORMATION
    SystemBadPageInformation = 128
    SystemProcessorProfileControlArea = 129  # q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
    SystemCombinePhysicalMemoryInformation = 130  # s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
    SystemEntropyInterruptTimingInformation = 131  # q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemConsoleInformation = 132  # q; s: SYSTEM_CONSOLE_INFORMATION
    SystemPlatformBinaryInformation = 133  # q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
    SystemPolicyInformation = 134  # q: SYSTEM_POLICY_INFORMATION
    SystemHypervisorProcessorCountInformation = 135  # q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
    SystemDeviceDataInformation = 136  # q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemDeviceDataEnumerationInformation = 137  # q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemMemoryTopologyInformation = 138  # q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
    SystemMemoryChannelInformation = 139  # q: SYSTEM_MEMORY_CHANNEL_INFORMATION
    SystemBootLogoInformation = 140  # q: SYSTEM_BOOT_LOGO_INFORMATION // 140
    SystemProcessorPerformanceInformationEx = 141  # q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // since WINBLUE
    SystemCriticalProcessErrorLogInformation = 142
    SystemSecureBootPolicyInformation = 143  # q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
    SystemPageFileInformationEx = 144  # q: SYSTEM_PAGEFILE_INFORMATION_EX
    SystemSecureBootInformation = 145  # q: SYSTEM_SECUREBOOT_INFORMATION
    SystemEntropyInterruptTimingRawInformation = 146
    SystemPortableWorkspaceEfiLauncherInformation = 147  # q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
    SystemFullProcessInformation = 148  # q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
    SystemKernelDebuggerInformationEx = 149  # q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
    SystemBootMetadataInformation = 150  # 150
    SystemSoftRebootInformation = 151  # q: ULONG
    SystemElamCertificateInformation = 152  # s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
    SystemOfflineDumpConfigInformation = 153  # q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
    SystemProcessorFeaturesInformation = 154  # q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
    SystemRegistryReconciliationInformation = 155  # s: NULL (requires admin) (flushes registry hives)
    SystemEdidInformation = 156  # q: SYSTEM_EDID_INFORMATION
    SystemManufacturingInformation = 157  # q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
    SystemEnergyEstimationConfigInformation = 158  # q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
    SystemHypervisorDetailInformation = 159  # q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
    SystemProcessorCycleStatsInformation = 160  # q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // 160
    SystemVmGenerationCountInformation = 161
    SystemTrustedPlatformModuleInformation = 162  # q: SYSTEM_TPM_INFORMATION
    SystemKernelDebuggerFlags = 163  # SYSTEM_KERNEL_DEBUGGER_FLAGS
    SystemCodeIntegrityPolicyInformation = 164  # q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
    SystemIsolatedUserModeInformation = 165  # q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
    SystemHardwareSecurityTestInterfaceResultsInformation = 166
    SystemSingleModuleInformation = 167  # q: SYSTEM_SINGLE_MODULE_INFORMATION
    SystemAllowedCpuSetsInformation = 168
    SystemVsmProtectionInformation = 169  # q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
    SystemInterruptCpuSetsInformation = 170  # q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
    SystemSecureBootPolicyFullInformation = 171  # q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
    SystemCodeIntegrityPolicyFullInformation = 172
    SystemAffinitizedInterruptProcessorInformation = 173  # (requires SeIncreaseBasePriorityPrivilege)
    SystemRootSiloInformation = 174  # q: SYSTEM_ROOT_SILO_INFORMATION
    SystemCpuSetInformation = 175  # q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
    SystemCpuSetTagInformation = 176  # q: SYSTEM_CPU_SET_TAG_INFORMATION
    SystemWin32WerStartCallout = 177
    SystemSecureKernelProfileInformation = 178  # q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
    SystemCodeIntegrityPlatformManifestInformation = 179  # q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
    SystemInterruptSteeringInformation = 180  # SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT // 180
    SystemSupportedProcessorArchitectures = 181  # p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
    SystemMemoryUsageInformation = 182  # q: SYSTEM_MEMORY_USAGE_INFORMATION
    SystemCodeIntegrityCertificateInformation = 183  # q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
    SystemPhysicalMemoryInformation = 184  # q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
    SystemControlFlowTransition = 185
    SystemKernelDebuggingAllowed = 186  # s: ULONG
    SystemActivityModerationExeState = 187  # SYSTEM_ACTIVITY_MODERATION_EXE_STATE
    SystemActivityModerationUserSettings = 188  # SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
    SystemCodeIntegrityPoliciesFullInformation = 189
    SystemCodeIntegrityUnlockInformation = 190  # SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
    SystemIntegrityQuotaInformation = 191
    SystemFlushInformation = 192  # q: SYSTEM_FLUSH_INFORMATION
    SystemProcessorIdleMaskInformation = 193  # q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
    SystemSecureDumpEncryptionInformation = 194
    SystemWriteConstraintInformation = 195  # SYSTEM_WRITE_CONSTRAINT_INFORMATION
    SystemKernelVaShadowInformation = 196  # SYSTEM_KERNEL_VA_SHADOW_INFORMATION
    SystemHypervisorSharedPageInformation = 197  # SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
    SystemFirmwareBootPerformanceInformation = 198
    SystemCodeIntegrityVerificationInformation = 199  # SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
    SystemFirmwarePartitionInformation = 200  # SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
    SystemSpeculationControlInformation = 201  # SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
    SystemDmaGuardPolicyInformation = 202  # SYSTEM_DMA_GUARD_POLICY_INFORMATION
    SystemEnclaveLaunchControlInformation = 203  # SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
    SystemWorkloadAllowedCpuSetsInformation = 204  # SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
    SystemCodeIntegrityUnlockModeInformation = 205
    SystemLeapSecondInformation = 206  # SYSTEM_LEAP_SECOND_INFORMATION
    SystemFlags2Information = 207  # q: SYSTEM_FLAGS_INFORMATION
    SystemSecurityModelInformation = 208  # SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
    SystemCodeIntegritySyntheticCacheInformation = 209
    SystemFeatureConfigurationInformation = 210  # SYSTEM_FEATURE_CONFIGURATION_INFORMATION // since 20H1 // 210
    SystemFeatureConfigurationSectionInformation = 211  # SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
    SystemFeatureUsageSubscriptionInformation = 212  # SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
    SystemSecureSpeculationControlInformation = 213  # SECURE_SPECULATION_CONTROL_INFORMATION
    SystemSpacesBootInformation = 214  # since 20H2
    SystemFwRamdiskInformation = 215  # SYSTEM_FIRMWARE_RAMDISK_INFORMATION
    SystemWheaIpmiHardwareInformation = 216
    SystemDifSetRuleClassInformation = 217
    SystemDifClearRuleClassInformation = 218
    SystemDifApplyPluginVerificationOnDriver = 219
    SystemDifRemovePluginVerificationOnDriver = 220  # 220
    SystemShadowStackInformation = 221  # SYSTEM_SHADOW_STACK_INFORMATION
    SystemBuildVersionInformation = 222  # SYSTEM_BUILD_VERSION_INFORMATION
    SystemPoolLimitInformation = 223  # SYSTEM_POOL_LIMIT_INFORMATION
    SystemCodeIntegrityAddDynamicStore = 224
    SystemCodeIntegrityClearDynamicStores = 225
    SystemDifPoolTrackingInformation = 226
    SystemPoolZeroingInformation = 227  # SYSTEM_POOL_ZEROING_INFORMATION
    SystemDpcWatchdogInformation = 228
    SystemDpcWatchdogInformation2 = 229
    SystemSupportedProcessorArchitectures2 = 230  # q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx  // 230
    SystemSingleProcessorRelationshipInformation = 231  # q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor)
    SystemXfgCheckFailureInformation = 232
    SystemIommuStateInformation = 233  # SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
    SystemHypervisorMinrootInformation = 234  # SYSTEM_HYPERVISOR_MINROOT_INFORMATION
    SystemHypervisorBootPagesInformation = 235  # SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
    SystemPointerAuthInformation = 236  # SYSTEM_POINTER_AUTH_INFORMATION
    SystemSecureKernelDebuggerInformation = 237
    SystemOriginalImageFeatureInformation = 238
    MaxSystemInfoClass = 239

class EVENT_TRACE_INFORMATION_CLASS(Enum):
    EventTraceKernelVersionInformation = 0  # EVENT_TRACE_VERSION_INFORMATION
    EventTraceGroupMaskInformation = 1  # EVENT_TRACE_GROUPMASK_INFORMATION
    EventTracePerformanceInformation = 2  # EVENT_TRACE_PERFORMANCE_INFORMATION
    EventTraceTimeProfileInformation = 3  # EVENT_TRACE_TIME_PROFILE_INFORMATION
    EventTraceSessionSecurityInformation = 4  # EVENT_TRACE_SESSION_SECURITY_INFORMATION
    EventTraceSpinlockInformation = 5  # EVENT_TRACE_SPINLOCK_INFORMATION
    EventTraceStackTracingInformation = 6  # EVENT_TRACE_SYSTEM_EVENT_INFORMATION
    EventTraceExecutiveResourceInformation = 7  # EVENT_TRACE_EXECUTIVE_RESOURCE_INFORMATION
    EventTraceHeapTracingInformation = 8  # EVENT_TRACE_HEAP_TRACING_INFORMATION
    EventTraceHeapSummaryTracingInformation = 9  # EVENT_TRACE_HEAP_TRACING_INFORMATION
    EventTracePoolTagFilterInformation = 10  # EVENT_TRACE_TAG_FILTER_INFORMATION
    EventTracePebsTracingInformation = 11  # EVENT_TRACE_SYSTEM_EVENT_INFORMATION
    EventTraceProfileConfigInformation = 12  # EVENT_TRACE_PROFILE_COUNTER_INFORMATION
    EventTraceProfileSourceListInformation = 13  # EVENT_TRACE_PROFILE_LIST_INFORMATION
    EventTraceProfileEventListInformation = 14  # EVENT_TRACE_SYSTEM_EVENT_INFORMATION
    EventTraceProfileCounterListInformation = 15  # EVENT_TRACE_PROFILE_COUNTER_INFORMATION
    EventTraceStackCachingInformation = 16  # EVENT_TRACE_STACK_CACHING_INFORMATION
    EventTraceObjectTypeFilterInformation = 17  # EVENT_TRACE_TAG_FILTER_INFORMATION
    EventTraceSoftRestartInformation = 18  # EVENT_TRACE_SOFT_RESTART_INFORMATION
    EventTraceLastBranchConfigurationInformation = 19  # REDSTONE3
    EventTraceLastBranchEventListInformation = 20
    EventTraceProfileSourceAddInformation = 21  # EVENT_TRACE_PROFILE_ADD_INFORMATION // REDSTONE4
    EventTraceProfileSourceRemoveInformation = 22  # EVENT_TRACE_PROFILE_REMOVE_INFORMATION
    EventTraceProcessorTraceConfigurationInformation = 23
    EventTraceProcessorTraceEventListInformation = 24
    EventTraceCoverageSamplerInformation = 25  # EVENT_TRACE_COVERAGE_SAMPLER_INFORMATION
    EventTraceUnifiedStackCachingInformation = 26  # sicne 21H1
    MaxEventTraceInfoClass = 27

class SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS(Enum):
    SystemCrashDumpDisable = 0
    SystemCrashDumpReconfigure = 1
    SystemCrashDumpInitializationComplete = 2

class WATCHDOG_HANDLER_ACTION(Enum):
    WdActionSetTimeoutValue = 0
    WdActionQueryTimeoutValue = 1
    WdActionResetTimer = 2
    WdActionStopTimer = 3
    WdActionStartTimer = 4
    WdActionSetTriggerAction = 5
    WdActionQueryTriggerAction = 6
    WdActionQueryState = 7

class WATCHDOG_INFORMATION_CLASS(Enum):
    WdInfoTimeoutValue = 0
    WdInfoResetTimer = 1
    WdInfoStopTimer = 2
    WdInfoStartTimer = 3
    WdInfoTriggerAction = 4
    WdInfoState = 5
    WdInfoTriggerReset = 6
    WdInfoNop = 7
    WdInfoGeneratedLastReset = 8
    WdInfoInvalid = 9

class SYSTEM_FIRMWARE_TABLE_ACTION(Enum):
    SystemFirmwareTableEnumerate = 0
    SystemFirmwareTableGet = 1
    SystemFirmwareTableMax = 2

class SYSTEM_MEMORY_LIST_COMMAND(Enum):
    MemoryCaptureAccessedBits = 0
    MemoryCaptureAndResetAccessedBits = 1
    MemoryEmptyWorkingSets = 2
    MemoryFlushModifiedList = 3
    MemoryPurgeStandbyList = 4
    MemoryPurgeLowPriorityStandbyList = 5
    MemoryCommandMax = 6

class COVERAGE_REQUEST_CODES(Enum):
    CoverageAllModules = 0
    CoverageSearchByHash = 1
    CoverageSearchByName = 2

class SYSTEM_VA_TYPE(Enum):
    SystemVaTypeAll = 0
    SystemVaTypeNonPagedPool = 1
    SystemVaTypePagedPool = 2
    SystemVaTypeSystemCache = 3
    SystemVaTypeSystemPtes = 4
    SystemVaTypeSessionSpace = 5
    SystemVaTypeMax = 6

class STORE_INFORMATION_CLASS(Enum):
    StorePageRequest = 1
    StoreStatsRequest = 2  # q: SM_STATS_REQUEST // SmProcessStatsRequest
    StoreCreateRequest = 3  # s: SM_CREATE_REQUEST (requires SeProfileSingleProcessPrivilege)
    StoreDeleteRequest = 4  # s: SM_DELETE_REQUEST (requires SeProfileSingleProcessPrivilege)
    StoreListRequest = 5  # q: SM_STORE_LIST_REQUEST / SM_STORE_LIST_REQUEST_EX // SmProcessListRequest
    Available1 = 6
    StoreEmptyRequest = 7
    CacheListRequest = 8  # q: SMC_CACHE_LIST_REQUEST // SmcProcessListRequest
    CacheCreateRequest = 9  # s: SMC_CACHE_CREATE_REQUEST (requires SeProfileSingleProcessPrivilege)
    CacheDeleteRequest = 10  # s: SMC_CACHE_DELETE_REQUEST (requires SeProfileSingleProcessPrivilege)
    CacheStoreCreateRequest = 11  # s: SMC_STORE_CREATE_REQUEST (requires SeProfileSingleProcessPrivilege)
    CacheStoreDeleteRequest = 12  # s: SMC_STORE_DELETE_REQUEST (requires SeProfileSingleProcessPrivilege)
    CacheStatsRequest = 13  # q: SMC_CACHE_STATS_REQUEST // SmcProcessStatsRequest
    Available2 = 14
    RegistrationRequest = 15  # q: SM_REGISTRATION_REQUEST (requires SeProfileSingleProcessPrivilege) // SmProcessRegistrationRequest
    GlobalCacheStatsRequest = 16
    StoreResizeRequest = 17  # s: SM_STORE_RESIZE_REQUEST (requires SeProfileSingleProcessPrivilege)
    CacheStoreResizeRequest = 18  # s: SMC_STORE_RESIZE_REQUEST (requires SeProfileSingleProcessPrivilege)
    SmConfigRequest = 19  # s: SM_CONFIG_REQUEST (requires SeProfileSingleProcessPrivilege)
    StoreHighMemoryPriorityRequest = 20  # s: SM_STORE_HIGH_MEM_PRIORITY_REQUEST (requires SeProfileSingleProcessPrivilege)
    SystemStoreTrimRequest = 21  # s: SM_SYSTEM_STORE_TRIM_REQUEST (requires SeProfileSingleProcessPrivilege)
    MemCompressionInfoRequest = 22  # q: SM_MEM_COMPRESSION_INFO_REQUEST // SmProcessCompressionInfoRequest
    ProcessStoreInfoRequest = 23  # SmProcessProcessStoreInfoRequest
    StoreInformationMax = 24

class ST_STATS_LEVEL(Enum):
    StStatsLevelBasic = 0
    StStatsLevelIoStats = 1
    StStatsLevelRegionSpace = 2  # requires SeProfileSingleProcessPrivilege
    StStatsLevelSpaceBitmap = 3  # requires SeProfileSingleProcessPrivilege
    StStatsLevelMax = 4

class SM_STORE_TYPE(Enum):
    StoreTypeInMemory = 0
    StoreTypeFile = 1
    StoreTypeMax = 2

class SM_STORE_MANAGER_TYPE(Enum):
    SmStoreManagerTypePhysical = 0
    SmStoreManagerTypeVirtual = 1
    SmStoreManagerTypeMax = 2

class SM_CONFIG_TYPE(Enum):
    SmConfigDirtyPageCompression = 0
    SmConfigAsyncInswap = 1
    SmConfigPrefetchSeekThreshold = 2
    SmConfigTypeMax = 3

class TPM_BOOT_ENTROPY_RESULT_CODE(Enum):
    TpmBootEntropyStructureUninitialized = 0
    TpmBootEntropyDisabledByPolicy = 1
    TpmBootEntropyNoTpmFound = 2
    TpmBootEntropyTpmError = 3
    TpmBootEntropySuccess = 4

class SYSTEM_PIXEL_FORMAT(Enum):
    SystemPixelFormatUnknown = 0
    SystemPixelFormatR8G8B8 = 1
    SystemPixelFormatR8G8B8X8 = 2
    SystemPixelFormatB8G8R8 = 3
    SystemPixelFormatB8G8R8X8 = 4

class SYSTEM_PROCESS_CLASSIFICATION(Enum):
    SystemProcessClassificationNormal = 0
    SystemProcessClassificationSystem = 1
    SystemProcessClassificationSecureSystem = 2
    SystemProcessClassificationMemCompression = 3
    SystemProcessClassificationRegistry = 4  # REDSTONE4
    SystemProcessClassificationMaximum = 5

class SYSTEM_ACTIVITY_MODERATION_STATE(Enum):
    SystemActivityModerationStateSystemManaged = 0
    SystemActivityModerationStateUserManagedAllowThrottling = 1
    SystemActivityModerationStateUserManagedDisableThrottling = 2
    MaxSystemActivityModerationState = 3

class SYSTEM_ACTIVITY_MODERATION_APP_TYPE(Enum):
    SystemActivityModerationAppTypeClassic = 0
    SystemActivityModerationAppTypePackaged = 1
    MaxSystemActivityModerationAppType = 2

class SYSTEM_IOMMU_STATE(Enum):
    IommuStateBlock = 0
    IommuStateUnblock = 1

class SYSDBG_COMMAND(Enum):
    SysDbgQueryModuleInformation = 0
    SysDbgQueryTraceInformation = 1
    SysDbgSetTracepoint = 2
    SysDbgSetSpecialCall = 3  # PVOID
    SysDbgClearSpecialCalls = 4  # void
    SysDbgQuerySpecialCalls = 5
    SysDbgBreakPoint = 6
    SysDbgQueryVersion = 7  # DBGKD_GET_VERSION64
    SysDbgReadVirtual = 8  # SYSDBG_VIRTUAL
    SysDbgWriteVirtual = 9  # SYSDBG_VIRTUAL
    SysDbgReadPhysical = 10  # SYSDBG_PHYSICAL // 10
    SysDbgWritePhysical = 11  # SYSDBG_PHYSICAL
    SysDbgReadControlSpace = 12  # SYSDBG_CONTROL_SPACE
    SysDbgWriteControlSpace = 13  # SYSDBG_CONTROL_SPACE
    SysDbgReadIoSpace = 14  # SYSDBG_IO_SPACE
    SysDbgWriteIoSpace = 15  # SYSDBG_IO_SPACE
    SysDbgReadMsr = 16  # SYSDBG_MSR
    SysDbgWriteMsr = 17  # SYSDBG_MSR
    SysDbgReadBusData = 18  # SYSDBG_BUS_DATA
    SysDbgWriteBusData = 19  # SYSDBG_BUS_DATA
    SysDbgCheckLowMemory = 20  # 20
    SysDbgEnableKernelDebugger = 21
    SysDbgDisableKernelDebugger = 22
    SysDbgGetAutoKdEnable = 23
    SysDbgSetAutoKdEnable = 24
    SysDbgGetPrintBufferSize = 25
    SysDbgSetPrintBufferSize = 26
    SysDbgGetKdUmExceptionEnable = 27
    SysDbgSetKdUmExceptionEnable = 28
    SysDbgGetTriageDump = 29  # SYSDBG_TRIAGE_DUMP
    SysDbgGetKdBlockEnable = 30  # 30
    SysDbgSetKdBlockEnable = 31
    SysDbgRegisterForUmBreakInfo = 32
    SysDbgGetUmBreakPid = 33
    SysDbgClearUmBreakPid = 34
    SysDbgGetUmAttachPid = 35
    SysDbgClearUmAttachPid = 36
    SysDbgGetLiveKernelDump = 37  # SYSDBG_LIVEDUMP_CONTROL
    SysDbgKdPullRemoteFile = 38  # SYSDBG_KD_PULL_REMOTE_FILE
    SysDbgMaxInfoClass = 39

class HARDERROR_RESPONSE_OPTION(Enum):
    OptionAbortRetryIgnore = 0
    OptionOk = 1
    OptionOkCancel = 2
    OptionRetryCancel = 3
    OptionYesNo = 4
    OptionYesNoCancel = 5
    OptionShutdownSystem = 6
    OptionOkNoWait = 7
    OptionCancelTryContinue = 8

class HARDERROR_RESPONSE(Enum):
    ResponseReturnToCaller = 0
    ResponseNotHandled = 1
    ResponseAbort = 2
    ResponseCancel = 3
    ResponseIgnore = 4
    ResponseNo = 5
    ResponseOk = 6
    ResponseRetry = 7
    ResponseYes = 8
    ResponseTryAgain = 9
    ResponseContinue = 10

class ALTERNATIVE_ARCHITECTURE_TYPE(Enum):
    StandardDesign = 0
    NEC98x86 = 1
    EndAlternatives = 2

class ATOM_INFORMATION_CLASS(Enum):
    AtomBasicInformation = 0
    AtomTableInformation = 1

class SHUTDOWN_ACTION(Enum):
    ShutdownNoReboot = 0
    ShutdownReboot = 1
    ShutdownPowerOff = 2
    ShutdownRebootForRecovery = 3  # since WIN11

class BCD_MESSAGE_TYPE(Enum):
    BCD_MESSAGE_TYPE_NONE = 0
    BCD_MESSAGE_TYPE_TRACE = 1
    BCD_MESSAGE_TYPE_INFORMATION = 2
    BCD_MESSAGE_TYPE_WARNING = 3
    BCD_MESSAGE_TYPE_ERROR = 4
    BCD_MESSAGE_TYPE_MAXIMUM = 5

class BCD_IMPORT_FLAGS(Enum):
    BCD_IMPORT_NONE = 0
    BCD_IMPORT_DELETE_FIRMWARE_OBJECTS = 1

class BCD_OPEN_FLAGS(Enum):
    BCD_OPEN_NONE = 0
    BCD_OPEN_OPEN_STORE_OFFLINE = 1
    BCD_OPEN_SYNC_FIRMWARE_ENTRIES = 2

class BCD_OBJECT_TYPE(Enum):
    BCD_OBJECT_TYPE_NONE = 0
    BCD_OBJECT_TYPE_APPLICATION = 1
    BCD_OBJECT_TYPE_INHERITED = 2
    BCD_OBJECT_TYPE_DEVICE = 3

class BCD_APPLICATION_OBJECT_TYPE(Enum):
    BCD_APPLICATION_OBJECT_NONE = 0
    BCD_APPLICATION_OBJECT_FIRMWARE_BOOT_MANAGER = 1
    BCD_APPLICATION_OBJECT_WINDOWS_BOOT_MANAGER = 2
    BCD_APPLICATION_OBJECT_WINDOWS_BOOT_LOADER = 3
    BCD_APPLICATION_OBJECT_WINDOWS_RESUME_APPLICATION = 4
    BCD_APPLICATION_OBJECT_MEMORY_TESTER = 5
    BCD_APPLICATION_OBJECT_LEGACY_NTLDR = 6
    BCD_APPLICATION_OBJECT_LEGACY_SETUPLDR = 7
    BCD_APPLICATION_OBJECT_BOOT_SECTOR = 8
    BCD_APPLICATION_OBJECT_STARTUP_MODULE = 9
    BCD_APPLICATION_OBJECT_GENERIC_APPLICATION = 10
    BCD_APPLICATION_OBJECT_RESERVED = 1048575

class BCD_APPLICATION_IMAGE_TYPE(Enum):
    BCD_APPLICATION_IMAGE_NONE = 0
    BCD_APPLICATION_IMAGE_FIRMWARE_APPLICATION = 1
    BCD_APPLICATION_IMAGE_BOOT_APPLICATION = 2
    BCD_APPLICATION_IMAGE_LEGACY_LOADER = 3
    BCD_APPLICATION_IMAGE_REALMODE_CODE = 4

class BCD_INHERITED_CLASS_TYPE(Enum):
    BCD_INHERITED_CLASS_NONE = 0
    BCD_INHERITED_CLASS_LIBRARY = 1
    BCD_INHERITED_CLASS_APPLICATION = 2
    BCD_INHERITED_CLASS_DEVICE = 3

class BCD_COPY_FLAGS(Enum):
    BCD_COPY_NONE = 0
    BCD_COPY_COPY_CREATE_NEW_OBJECT_IDENTIFIER = 1
    BCD_COPY_COPY_DELETE_EXISTING_OBJECT = 2
    BCD_COPY_COPY_UNKNOWN_FIRMWARE_APPLICATION = 4
    BCD_COPY_IGNORE_SETUP_TEMPLATE_ELEMENTS = 8
    BCD_COPY_RETAIN_ELEMENT_DATA = 16
    BCD_COPY_MIGRATE_ELEMENT_DATA = 32

class BCD_ELEMENT_DATATYPE_FORMAT(Enum):
    BCD_ELEMENT_DATATYPE_FORMAT_UNKNOWN = 0
    BCD_ELEMENT_DATATYPE_FORMAT_DEVICE = 1  # 0x01000000
    BCD_ELEMENT_DATATYPE_FORMAT_STRING = 2  # 0x02000000
    BCD_ELEMENT_DATATYPE_FORMAT_OBJECT = 3  # 0x03000000
    BCD_ELEMENT_DATATYPE_FORMAT_OBJECTLIST = 4  # 0x04000000
    BCD_ELEMENT_DATATYPE_FORMAT_INTEGER = 5  # 0x05000000
    BCD_ELEMENT_DATATYPE_FORMAT_BOOLEAN = 6  # 0x06000000
    BCD_ELEMENT_DATATYPE_FORMAT_INTEGERLIST = 7  # 0x07000000
    BCD_ELEMENT_DATATYPE_FORMAT_BINARY = 8  # 0x08000000

class BCD_ELEMENT_DATATYPE_CLASS(Enum):
    BCD_ELEMENT_DATATYPE_CLASS_NONE = 0
    BCD_ELEMENT_DATATYPE_CLASS_LIBRARY = 1
    BCD_ELEMENT_DATATYPE_CLASS_APPLICATION = 2
    BCD_ELEMENT_DATATYPE_CLASS_DEVICE = 3
    BCD_ELEMENT_DATATYPE_CLASS_SETUPTEMPLATE = 4
    BCD_ELEMENT_DATATYPE_CLASS_OEM = 5

class BCD_ELEMENT_DEVICE_TYPE(Enum):
    BCD_ELEMENT_DEVICE_TYPE_NONE = 0
    BCD_ELEMENT_DEVICE_TYPE_BOOT_DEVICE = 1
    BCD_ELEMENT_DEVICE_TYPE_PARTITION = 2
    BCD_ELEMENT_DEVICE_TYPE_FILE = 3
    BCD_ELEMENT_DEVICE_TYPE_RAMDISK = 4
    BCD_ELEMENT_DEVICE_TYPE_UNKNOWN = 5
    BCD_ELEMENT_DEVICE_TYPE_QUALIFIED_PARTITION = 6
    BCD_ELEMENT_DEVICE_TYPE_VMBUS = 7
    BCD_ELEMENT_DEVICE_TYPE_LOCATE_DEVICE = 8
    BCD_ELEMENT_DEVICE_TYPE_URI = 9
    BCD_ELEMENT_DEVICE_TYPE_COMPOSITE = 10

class BCD_FLAGS(Enum):
    BCD_FLAG_NONE = 0
    BCD_FLAG_QUALIFIED_PARTITION = 1
    BCD_FLAG_NO_DEVICE_TRANSLATION = 2
    BCD_FLAG_ENUMERATE_INHERITED_OBJECTS = 4
    BCD_FLAG_ENUMERATE_DEVICE_OPTIONS = 8
    BCD_FLAG_OBSERVE_PRECEDENCE = 16
    BCD_FLAG_DISABLE_VHD_NT_TRANSLATION = 32
    BCD_FLAG_DISABLE_VHD_DEVICE_DETECTION = 64
    BCD_FLAG_DISABLE_POLICY_CHECKS = 128

class BcdBootMgrElementTypes(Enum):
    BcdBootMgrObjectList_DisplayOrder = 603979777
    BcdBootMgrObjectList_BootSequence = 603979778
    BcdBootMgrObject_DefaultObject = 587202563
    BcdBootMgrInteger_Timeout = 620756996
    BcdBootMgrBoolean_AttemptResume = 637534213
    BcdBootMgrObject_ResumeObject = 587202566
    BcdBootMgrObjectList_StartupSequence = 603979783
    BcdBootMgrObjectList_ToolsDisplayOrder = 603979792
    BcdBootMgrBoolean_DisplayBootMenu = 637534240
    BcdBootMgrBoolean_NoErrorDisplay = 637534241
    BcdBootMgrDevice_BcdDevice = 553648162
    BcdBootMgrString_BcdFilePath = 570425379
    BcdBootMgrBoolean_HormEnabled = 637534244
    BcdBootMgrBoolean_HiberRoot = 637534245
    BcdBootMgrString_PasswordOverride = 570425382
    BcdBootMgrString_PinpassPhraseOverride = 570425383
    BcdBootMgrBoolean_ProcessCustomActionsFirst = 637534248
    BcdBootMgrIntegerList_CustomActionsList = 654311472
    BcdBootMgrBoolean_PersistBootSequence = 637534257
    BcdBootMgrBoolean_SkipStartupSequence = 637534258

class BcdLibrary_FirstMegabytePolicy(Enum):
    FirstMegabytePolicyUseNone = 0
    FirstMegabytePolicyUseAll = 1
    FirstMegabytePolicyUsePrivate = 2

class BcdLibrary_DebuggerType(Enum):
    DebuggerSerial = 0
    Debugger1394 = 1
    DebuggerUsb = 2
    DebuggerNet = 3
    DebuggerLocal = 4

class BcdLibrary_DebuggerStartPolicy(Enum):
    DebuggerStartActive = 0
    DebuggerStartAutoEnable = 1
    DebuggerStartDisable = 2

class BcdLibrary_ConfigAccessPolicy(Enum):
    ConfigAccessPolicyDefault = 0
    ConfigAccessPolicyDisallowMmConfig = 1

class BcdLibrary_UxDisplayMessageType(Enum):
    DisplayMessageTypeDefault = 0
    DisplayMessageTypeResume = 1
    DisplayMessageTypeHyperV = 2
    DisplayMessageTypeRecovery = 3
    DisplayMessageTypeStartupRepair = 4
    DisplayMessageTypeSystemImageRecovery = 5
    DisplayMessageTypeCommandPrompt = 6
    DisplayMessageTypeSystemRestore = 7
    DisplayMessageTypePushButtonReset = 8

class BcdLibrary_SafeBoot(Enum):
    SafemodeMinimal = 0
    SafemodeNetwork = 1
    SafemodeDsRepair = 2

class BcdLibraryElementTypes(Enum):
    BcdLibraryDevice_ApplicationDevice = 285212673
    BcdLibraryString_ApplicationPath = 301989890
    BcdLibraryString_Description = 301989892
    BcdLibraryString_PreferredLocale = 301989893
    BcdLibraryObjectList_InheritedObjects = 335544326
    BcdLibraryInteger_TruncatePhysicalMemory = 352321543
    BcdLibraryObjectList_RecoverySequence = 335544328
    BcdLibraryBoolean_AutoRecoveryEnabled = 369098761
    BcdLibraryIntegerList_BadMemoryList = 385875978
    BcdLibraryBoolean_AllowBadMemoryAccess = 369098763
    BcdLibraryInteger_FirstMegabytePolicy = 352321548
    BcdLibraryInteger_RelocatePhysicalMemory = 352321549
    BcdLibraryInteger_AvoidLowPhysicalMemory = 352321550
    BcdLibraryBoolean_TraditionalKsegMappings = 369098767
    BcdLibraryBoolean_DebuggerEnabled = 369098768
    BcdLibraryInteger_DebuggerType = 352321553
    BcdLibraryInteger_SerialDebuggerPortAddress = 352321554
    BcdLibraryInteger_SerialDebuggerPort = 352321555
    BcdLibraryInteger_SerialDebuggerBaudRate = 352321556
    BcdLibraryInteger_1394DebuggerChannel = 352321557
    BcdLibraryString_UsbDebuggerTargetName = 301989910
    BcdLibraryBoolean_DebuggerIgnoreUsermodeExceptions = 369098775
    BcdLibraryInteger_DebuggerStartPolicy = 352321560
    BcdLibraryString_DebuggerBusParameters = 301989913
    BcdLibraryInteger_DebuggerNetHostIP = 352321562
    BcdLibraryInteger_DebuggerNetPort = 352321563
    BcdLibraryBoolean_DebuggerNetDhcp = 369098780
    BcdLibraryString_DebuggerNetKey = 301989917
    BcdLibraryBoolean_DebuggerNetVM = 369098782
    BcdLibraryString_DebuggerNetHostIpv6 = 301989919
    BcdLibraryBoolean_EmsEnabled = 369098784
    BcdLibraryInteger_EmsPort = 352321570
    BcdLibraryInteger_EmsBaudRate = 352321571
    BcdLibraryString_LoadOptionsString = 301989936
    BcdLibraryBoolean_AttemptNonBcdStart = 369098801
    BcdLibraryBoolean_DisplayAdvancedOptions = 369098816
    BcdLibraryBoolean_DisplayOptionsEdit = 369098817
    BcdLibraryInteger_FVEKeyRingAddress = 352321602
    BcdLibraryDevice_BsdLogDevice = 285212739
    BcdLibraryString_BsdLogPath = 301989956
    BcdLibraryBoolean_BsdPreserveLog = 369098821
    BcdLibraryBoolean_GraphicsModeDisabled = 369098822
    BcdLibraryInteger_ConfigAccessPolicy = 352321607
    BcdLibraryBoolean_DisableIntegrityChecks = 369098824
    BcdLibraryBoolean_AllowPrereleaseSignatures = 369098825
    BcdLibraryString_FontPath = 301989962
    BcdLibraryInteger_SiPolicy = 352321611
    BcdLibraryInteger_FveBandId = 352321612
    BcdLibraryBoolean_ConsoleExtendedInput = 369098832
    BcdLibraryInteger_InitialConsoleInput = 352321617
    BcdLibraryInteger_GraphicsResolution = 352321618
    BcdLibraryBoolean_RestartOnFailure = 369098835
    BcdLibraryBoolean_GraphicsForceHighestMode = 369098836
    BcdLibraryBoolean_IsolatedExecutionContext = 369098848
    BcdLibraryInteger_BootUxDisplayMessage = 352321637
    BcdLibraryInteger_BootUxDisplayMessageOverride = 352321638
    BcdLibraryBoolean_BootUxLogoDisable = 369098855
    BcdLibraryBoolean_BootUxTextDisable = 369098856
    BcdLibraryBoolean_BootUxProgressDisable = 369098857
    BcdLibraryBoolean_BootUxFadeDisable = 369098858
    BcdLibraryBoolean_BootUxReservePoolDebug = 369098859
    BcdLibraryBoolean_BootUxDisable = 369098860
    BcdLibraryInteger_BootUxFadeFrames = 352321645
    BcdLibraryBoolean_BootUxDumpStats = 369098862
    BcdLibraryBoolean_BootUxShowStats = 369098863
    BcdLibraryBoolean_MultiBootSystem = 369098865
    BcdLibraryBoolean_ForceNoKeyboard = 369098866
    BcdLibraryInteger_AliasWindowsKey = 352321651
    BcdLibraryBoolean_BootShutdownDisabled = 369098868
    BcdLibraryInteger_PerformanceFrequency = 352321653
    BcdLibraryInteger_SecurebootRawPolicy = 352321654
    BcdLibraryIntegerList_AllowedInMemorySettings = 352321655
    BcdLibraryInteger_BootUxBitmapTransitionTime = 352321657
    BcdLibraryBoolean_TwoBootImages = 369098874
    BcdLibraryBoolean_ForceFipsCrypto = 369098875
    BcdLibraryInteger_BootErrorUx = 352321661
    BcdLibraryBoolean_AllowFlightSignatures = 369098878
    BcdLibraryInteger_BootMeasurementLogFormat = 352321663
    BcdLibraryInteger_DisplayRotation = 352321664
    BcdLibraryInteger_LogControl = 352321665
    BcdLibraryBoolean_NoFirmwareSync = 369098882
    BcdLibraryDevice_WindowsSystemDevice = 285212804
    BcdLibraryBoolean_NumLockOn = 369098887
    BcdLibraryString_AdditionalCiPolicy = 301990024

class BcdTemplateElementTypes(Enum):
    BcdSetupInteger_DeviceType = 1157627905
    BcdSetupString_ApplicationRelativePath = 1107296258
    BcdSetupString_RamdiskDeviceRelativePath = 1107296259
    BcdSetupBoolean_OmitOsLoaderElements = 1174405124
    BcdSetupIntegerList_ElementsToMigrateList = 1191182342
    BcdSetupBoolean_RecoveryOs = 1174405136

class BcdOSLoader_NxPolicy(Enum):
    NxPolicyOptIn = 0
    NxPolicyOptOut = 1
    NxPolicyAlwaysOff = 2
    NxPolicyAlwaysOn = 3

class BcdOSLoader_PAEPolicy(Enum):
    PaePolicyDefault = 0
    PaePolicyForceEnable = 1
    PaePolicyForceDisable = 2

class BcdOSLoader_BootStatusPolicy(Enum):
    BootStatusPolicyDisplayAllFailures = 0
    BootStatusPolicyIgnoreAllFailures = 1
    BootStatusPolicyIgnoreShutdownFailures = 2
    BootStatusPolicyIgnoreBootFailures = 3
    BootStatusPolicyIgnoreCheckpointFailures = 4
    BootStatusPolicyDisplayShutdownFailures = 5
    BootStatusPolicyDisplayBootFailures = 6
    BootStatusPolicyDisplayCheckpointFailures = 7

class BcdOSLoaderElementTypes(Enum):
    BcdOSLoaderDevice_OSDevice = 553648129
    BcdOSLoaderString_SystemRoot = 570425346
    BcdOSLoaderObject_AssociatedResumeObject = 587202563
    BcdOSLoaderBoolean_StampDisks = 637534212
    BcdOSLoaderBoolean_DetectKernelAndHal = 637534224
    BcdOSLoaderString_KernelPath = 570425361
    BcdOSLoaderString_HalPath = 570425362
    BcdOSLoaderString_DbgTransportPath = 570425363
    BcdOSLoaderInteger_NxPolicy = 620757024
    BcdOSLoaderInteger_PAEPolicy = 620757025
    BcdOSLoaderBoolean_WinPEMode = 637534242
    BcdOSLoaderBoolean_DisableCrashAutoReboot = 637534244
    BcdOSLoaderBoolean_UseLastGoodSettings = 637534245
    BcdOSLoaderBoolean_DisableCodeIntegrityChecks = 637534246
    BcdOSLoaderBoolean_AllowPrereleaseSignatures = 637534247
    BcdOSLoaderBoolean_NoLowMemory = 637534256
    BcdOSLoaderInteger_RemoveMemory = 620757041
    BcdOSLoaderInteger_IncreaseUserVa = 620757042
    BcdOSLoaderInteger_PerformaceDataMemory = 620757043
    BcdOSLoaderBoolean_UseVgaDriver = 637534272
    BcdOSLoaderBoolean_DisableBootDisplay = 637534273
    BcdOSLoaderBoolean_DisableVesaBios = 637534274
    BcdOSLoaderBoolean_DisableVgaMode = 637534275
    BcdOSLoaderInteger_ClusterModeAddressing = 620757072
    BcdOSLoaderBoolean_UsePhysicalDestination = 637534289
    BcdOSLoaderInteger_RestrictApicCluster = 620757074
    BcdOSLoaderString_OSLoaderTypeEVStore = 570425427
    BcdOSLoaderBoolean_UseLegacyApicMode = 637534292
    BcdOSLoaderInteger_X2ApicPolicy = 620757077
    BcdOSLoaderBoolean_UseBootProcessorOnly = 637534304
    BcdOSLoaderInteger_NumberOfProcessors = 620757089
    BcdOSLoaderBoolean_ForceMaximumProcessors = 637534306
    BcdOSLoaderBoolean_ProcessorConfigurationFlags = 620757091
    BcdOSLoaderBoolean_MaximizeGroupsCreated = 637534308
    BcdOSLoaderBoolean_ForceGroupAwareness = 637534309
    BcdOSLoaderInteger_GroupSize = 620757094
    BcdOSLoaderInteger_UseFirmwarePciSettings = 637534320
    BcdOSLoaderInteger_MsiPolicy = 620757105
    BcdOSLoaderInteger_PciExpressPolicy = 620757106
    BcdOSLoaderInteger_SafeBoot = 620757120
    BcdOSLoaderBoolean_SafeBootAlternateShell = 637534337
    BcdOSLoaderBoolean_BootLogInitialization = 637534352
    BcdOSLoaderBoolean_VerboseObjectLoadMode = 637534353
    BcdOSLoaderBoolean_KernelDebuggerEnabled = 637534368
    BcdOSLoaderBoolean_DebuggerHalBreakpoint = 637534369
    BcdOSLoaderBoolean_UsePlatformClock = 637534370
    BcdOSLoaderBoolean_ForceLegacyPlatform = 637534371
    BcdOSLoaderBoolean_UsePlatformTick = 637534372
    BcdOSLoaderBoolean_DisableDynamicTick = 637534373
    BcdOSLoaderInteger_TscSyncPolicy = 620757158
    BcdOSLoaderBoolean_EmsEnabled = 637534384
    BcdOSLoaderInteger_ForceFailure = 620757184
    BcdOSLoaderInteger_DriverLoadFailurePolicy = 620757185
    BcdOSLoaderInteger_BootMenuPolicy = 620757186
    BcdOSLoaderBoolean_AdvancedOptionsOneTime = 637534403
    BcdOSLoaderBoolean_OptionsEditOneTime = 637534404
    BcdOSLoaderInteger_BootStatusPolicy = 620757216
    BcdOSLoaderBoolean_DisableElamDrivers = 637534433
    BcdOSLoaderInteger_HypervisorLaunchType = 620757232
    BcdOSLoaderString_HypervisorPath = 620757233
    BcdOSLoaderBoolean_HypervisorDebuggerEnabled = 637534450
    BcdOSLoaderInteger_HypervisorDebuggerType = 620757235
    BcdOSLoaderInteger_HypervisorDebuggerPortNumber = 620757236
    BcdOSLoaderInteger_HypervisorDebuggerBaudrate = 620757237
    BcdOSLoaderInteger_HypervisorDebugger1394Channel = 620757238
    BcdOSLoaderInteger_BootUxPolicy = 620757239
    BcdOSLoaderInteger_HypervisorSlatDisabled = 570425592
    BcdOSLoaderString_HypervisorDebuggerBusParams = 570425593
    BcdOSLoaderInteger_HypervisorNumProc = 620757242
    BcdOSLoaderInteger_HypervisorRootProcPerNode = 620757243
    BcdOSLoaderBoolean_HypervisorUseLargeVTlb = 637534460
    BcdOSLoaderInteger_HypervisorDebuggerNetHostIp = 620757245
    BcdOSLoaderInteger_HypervisorDebuggerNetHostPort = 620757246
    BcdOSLoaderInteger_HypervisorDebuggerPages = 620757247
    BcdOSLoaderInteger_TpmBootEntropyPolicy = 620757248
    BcdOSLoaderString_HypervisorDebuggerNetKey = 570425616
    BcdOSLoaderString_HypervisorProductSkuType = 570425618
    BcdOSLoaderInteger_HypervisorRootProc = 570425619
    BcdOSLoaderBoolean_HypervisorDebuggerNetDhcp = 637534484
    BcdOSLoaderInteger_HypervisorIommuPolicy = 620757269
    BcdOSLoaderBoolean_HypervisorUseVApic = 637534486
    BcdOSLoaderString_HypervisorLoadOptions = 570425623
    BcdOSLoaderInteger_HypervisorMsrFilterPolicy = 620757272
    BcdOSLoaderInteger_HypervisorMmioNxPolicy = 620757273
    BcdOSLoaderInteger_HypervisorSchedulerType = 620757274
    BcdOSLoaderString_HypervisorRootProcNumaNodes = 570425627
    BcdOSLoaderInteger_HypervisorPerfmon = 620757276
    BcdOSLoaderInteger_HypervisorRootProcPerCore = 620757277
    BcdOSLoaderString_HypervisorRootProcNumaNodeLps = 570425630
    BcdOSLoaderInteger_XSavePolicy = 620757280
    BcdOSLoaderInteger_XSaveAddFeature0 = 620757281
    BcdOSLoaderInteger_XSaveAddFeature1 = 620757282
    BcdOSLoaderInteger_XSaveAddFeature2 = 620757283
    BcdOSLoaderInteger_XSaveAddFeature3 = 620757284
    BcdOSLoaderInteger_XSaveAddFeature4 = 620757285
    BcdOSLoaderInteger_XSaveAddFeature5 = 620757286
    BcdOSLoaderInteger_XSaveAddFeature6 = 620757287
    BcdOSLoaderInteger_XSaveAddFeature7 = 620757288
    BcdOSLoaderInteger_XSaveRemoveFeature = 620757289
    BcdOSLoaderInteger_XSaveProcessorsMask = 620757290
    BcdOSLoaderInteger_XSaveDisable = 620757291
    BcdOSLoaderInteger_KernelDebuggerType = 620757292
    BcdOSLoaderString_KernelDebuggerBusParameters = 570425645
    BcdOSLoaderInteger_KernelDebuggerPortAddress = 620757294
    BcdOSLoaderInteger_KernelDebuggerPortNumber = 620757295
    BcdOSLoaderInteger_ClaimedTpmCounter = 620757296
    BcdOSLoaderInteger_KernelDebugger1394Channel = 620757297
    BcdOSLoaderString_KernelDebuggerUsbTargetname = 570425650
    BcdOSLoaderInteger_KernelDebuggerNetHostIp = 620757299
    BcdOSLoaderInteger_KernelDebuggerNetHostPort = 620757300
    BcdOSLoaderBoolean_KernelDebuggerNetDhcp = 637534517
    BcdOSLoaderString_KernelDebuggerNetKey = 570425654
    BcdOSLoaderString_IMCHiveName = 570425655
    BcdOSLoaderDevice_IMCDevice = 553648440
    BcdOSLoaderInteger_KernelDebuggerBaudrate = 620757305
    BcdOSLoaderString_ManufacturingMode = 570425664
    BcdOSLoaderBoolean_EventLoggingEnabled = 637534529
    BcdOSLoaderInteger_VsmLaunchType = 620757314
    BcdOSLoaderInteger_HypervisorEnforcedCodeIntegrity = 620757316
    BcdOSLoaderBoolean_DtraceEnabled = 637534533
    BcdOSLoaderDevice_SystemDataDevice = 553648464
    BcdOSLoaderDevice_OsArcDevice = 553648465
    BcdOSLoaderDevice_OsDataDevice = 553648467
    BcdOSLoaderDevice_BspDevice = 553648468
    BcdOSLoaderDevice_BspFilepath = 553648469
    BcdOSLoaderString_KernelDebuggerNetHostIpv6 = 570425686
    BcdOSLoaderString_HypervisorDebuggerNetHostIpv6 = 570425697

class MEMORY_INFORMATION_CLASS(Enum):
    MemoryBasicInformation = 0  # MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation = 1  # MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation = 2  # UNICODE_STRING
    MemoryRegionInformation = 3  # MEMORY_REGION_INFORMATION
    MemoryWorkingSetExInformation = 4  # MEMORY_WORKING_SET_EX_INFORMATION // since VISTA
    MemorySharedCommitInformation = 5  # MEMORY_SHARED_COMMIT_INFORMATION // since WIN8
    MemoryImageInformation = 6  # MEMORY_IMAGE_INFORMATION
    MemoryRegionInformationEx = 7  # MEMORY_REGION_INFORMATION
    MemoryPrivilegedBasicInformation = 8
    MemoryEnclaveImageInformation = 9  # MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
    MemoryBasicInformationCapped = 10  # 10
    MemoryPhysicalContiguityInformation = 11  # MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
    MemoryBadInformation = 12  # since WIN11
    MemoryBadInformationAllProcesses = 13  # since 22H1
    MaxMemoryInfoClass = 14

class MEMORY_WORKING_SET_EX_LOCATION(Enum):
    MemoryLocationInvalid = 0
    MemoryLocationResident = 1
    MemoryLocationPagefile = 2
    MemoryLocationReserved = 3

class MEMORY_PHYSICAL_CONTIGUITY_UNIT_STATE(Enum):
    MemoryNotContiguous = 0
    MemoryAlignedAndContiguous = 1
    MemoryNotResident = 2
    MemoryNotEligibleToMakeContiguous = 3
    MemoryContiguityStateMax = 4

class SECTION_INFORMATION_CLASS(Enum):
    SectionBasicInformation = 0  # q; SECTION_BASIC_INFORMATION
    SectionImageInformation = 1  # q; SECTION_IMAGE_INFORMATION
    SectionRelocationInformation = 2  # q; PVOID RelocationAddress // name:wow64:whNtQuerySection_SectionRelocationInformation // since WIN7
    SectionOriginalBaseInformation = 3  # PVOID BaseAddress
    SectionInternalImageInformation = 4  # SECTION_INTERNAL_IMAGE_INFORMATION // since REDSTONE2
    MaxSectionInfoClass = 5

class SECTION_INHERIT(Enum):
    ViewShare = 1
    ViewUnmap = 2

class VIRTUAL_MEMORY_INFORMATION_CLASS(Enum):
    VmPrefetchInformation = 0  # ULONG
    VmPagePriorityInformation = 1  # OFFER_PRIORITY
    VmCfgCallTargetInformation = 2  # CFG_CALL_TARGET_LIST_INFORMATION // REDSTONE2
    VmPageDirtyStateInformation = 3  # REDSTONE3
    VmImageHotPatchInformation = 4  # 19H1
    VmPhysicalContiguityInformation = 5  # 20H1
    VmVirtualMachinePrepopulateInformation = 6
    VmRemoveFromWorkingSetInformation = 7
    MaxVmInfoClass = 8

class PARTITION_INFORMATION_CLASS(Enum):
    SystemMemoryPartitionInformation = 0  # q: MEMORY_PARTITION_CONFIGURATION_INFORMATION
    SystemMemoryPartitionMoveMemory = 1  # s: MEMORY_PARTITION_TRANSFER_INFORMATION
    SystemMemoryPartitionAddPagefile = 2  # s: MEMORY_PARTITION_PAGEFILE_INFORMATION
    SystemMemoryPartitionCombineMemory = 3  # q; s: MEMORY_PARTITION_PAGE_COMBINE_INFORMATION
    SystemMemoryPartitionInitialAddMemory = 4  # q; s: MEMORY_PARTITION_INITIAL_ADD_INFORMATION
    SystemMemoryPartitionGetMemoryEvents = 5  # MEMORY_PARTITION_MEMORY_EVENTS_INFORMATION // since REDSTONE2
    SystemMemoryPartitionSetAttributes = 6
    SystemMemoryPartitionNodeInformation = 7
    SystemMemoryPartitionCreateLargePages = 8
    SystemMemoryPartitionDedicatedMemoryInformation = 9
    SystemMemoryPartitionOpenDedicatedMemory = 10  # 10
    SystemMemoryPartitionMemoryChargeAttributes = 11
    SystemMemoryPartitionClearAttributes = 12
    SystemMemoryPartitionSetMemoryThresholds = 13  # since WIN11
    SystemMemoryPartitionMax = 14

class OBJECT_INFORMATION_CLASS(Enum):
    ObjectBasicInformation = 0  # q: OBJECT_BASIC_INFORMATION
    ObjectNameInformation = 1  # q: OBJECT_NAME_INFORMATION
    ObjectTypeInformation = 2  # q: OBJECT_TYPE_INFORMATION
    ObjectTypesInformation = 3  # q: OBJECT_TYPES_INFORMATION
    ObjectHandleFlagInformation = 4  # qs: OBJECT_HANDLE_FLAG_INFORMATION
    ObjectSessionInformation = 5  # s: void // change object session // (requires SeTcbPrivilege)
    ObjectSessionObjectInformation = 6  # s: void // change object session // (requires SeTcbPrivilege)
    MaxObjectInfoClass = 7

class BOUNDARY_ENTRY_TYPE(Enum):
    OBNS_Invalid = 0
    OBNS_Name = 1
    OBNS_SID = 2
    OBNS_IL = 3

class SYMBOLIC_LINK_INFO_CLASS(Enum):
    SymbolicLinkGlobalInformation = 1  # s: ULONG
    SymbolicLinkAccessMask = 2  # s: ACCESS_MASK
    MaxnSymbolicLinkInfoClass = 3

class PROCESSINFOCLASS(Enum):
    ProcessBasicInformation = 0  # q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits = 1  # qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters = 2  # q: IO_COUNTERS
    ProcessVmCounters = 3  # q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes = 4  # q: KERNEL_USER_TIMES
    ProcessBasePriority = 5  # s: KPRIORITY
    ProcessRaisePriority = 6  # s: ULONG
    ProcessDebugPort = 7  # q: HANDLE
    ProcessExceptionPort = 8  # s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
    ProcessAccessToken = 9  # s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation = 10  # qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize = 11  # s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode = 12  # qs: ULONG
    ProcessIoPortHandlers = 13  # (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
    ProcessPooledUsageAndLimits = 14  # q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch = 15  # q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL = 16  # qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup = 17  # s: BOOLEAN
    ProcessPriorityClass = 18  # qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information = 19  # qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount = 20  # q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask = 21  # (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost = 22  # qs: ULONG
    ProcessDeviceMap = 23  # qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation = 24  # q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation = 25  # s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information = 26  # q: ULONG_PTR
    ProcessImageFileName = 27  # q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled = 28  # q: ULONG
    ProcessBreakOnTermination = 29  # qs: ULONG
    ProcessDebugObjectHandle = 30  # q: HANDLE // 30
    ProcessDebugFlags = 31  # qs: ULONG
    ProcessHandleTracing = 32  # q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
    ProcessIoPriority = 33  # qs: IO_PRIORITY_HINT
    ProcessExecuteFlags = 34  # qs: ULONG
    ProcessTlsInformation = 35  # PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie = 36  # q: ULONG
    ProcessImageInformation = 37  # q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime = 38  # q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority = 39  # qs: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback = 40  # s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation = 41  # s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx = 42  # q: PROCESS_WS_WATCH_INFORMATION_EX[]
    ProcessImageFileNameWin32 = 43  # q: UNICODE_STRING
    ProcessImageFileMapping = 44  # q: HANDLE (input)
    ProcessAffinityUpdateMode = 45  # qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode = 46  # qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation = 47  # q: USHORT[]
    ProcessTokenVirtualizationEnabled = 48  # s: ULONG
    ProcessConsoleHostProcess = 49  # q: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation = 50  # q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation = 51  # q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy = 52  # s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation = 53
    ProcessHandleCheckingMode = 54  # qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount = 55  # q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles = 56  # s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl = 57  # s: PROCESS_WORKING_SET_CONTROL
    ProcessHandleTable = 58  # q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode = 59  # qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation = 60  # q: UNICODE_STRING // 60
    ProcessProtectionInformation = 61  # q: PS_PROTECTION
    ProcessMemoryExhaustion = 62  # PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation = 63  # PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation = 64  # q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation = 65  # PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation = 66  # SYSTEM_CPU_SET_INFORMATION[5]
    ProcessAllowedCpuSetsInformation = 67  # SYSTEM_CPU_SET_INFORMATION[5]
    ProcessSubsystemProcess = 68
    ProcessJobMemoryInformation = 69  # q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate = 70  # s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose = 71  # qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse = 72
    ProcessChildProcessInformation = 73  # q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation = 74  # qs: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation = 75  # q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues = 76  # q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    ProcessPowerThrottlingState = 77  # qs: POWER_THROTTLING_PROCESS_STATE
    ProcessReserved3Information = 78  # ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    ProcessWin32kSyscallFilterInformation = 79  # q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets = 80  # 80
    ProcessWakeInformation = 81  # PROCESS_WAKE_INFORMATION
    ProcessEnergyTrackingState = 82  # PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory = 83  # MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump = 84
    ProcessTelemetryCoverage = 85
    ProcessEnclaveInformation = 86
    ProcessEnableReadWriteVmLogging = 87  # PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation = 88  # q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection = 89  # q: HANDLE
    ProcessDebugAuthInformation = 90  # since REDSTONE4 // 90
    ProcessSystemResourceManagement = 91  # PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber = 92  # q: ULONGLONG
    ProcessLoaderDetour = 93  # since REDSTONE5
    ProcessSecurityDomainInformation = 94  # PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation = 95  # PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging = 96  # PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation = 97  # PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation = 98  # PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation = 99  # PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation = 100  # qs: BOOLEAN (kernel-mode only) // INT2E // since 20H1 // 100
    ProcessDynamicEHContinuationTargets = 101  # PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges = 102  # PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange = 103  # since WIN11
    ProcessApplyStateChange = 104
    ProcessEnableOptionalXStateFeatures = 105
    ProcessAltPrefetchParam = 106  # since 22H1
    ProcessAssignCpuPartitions = 107
    ProcessPriorityClassEx = 108  # s: PROCESS_PRIORITY_CLASS_EX
    ProcessMembershipInformation = 109
    ProcessEffectiveIoPriority = 110  # q: IO_PRIORITY_HINT
    ProcessEffectivePagePriority = 111  # q: ULONG
    MaxProcessInfoClass = 112

class THREADINFOCLASS(Enum):
    ThreadBasicInformation = 0  # q: THREAD_BASIC_INFORMATION
    ThreadTimes = 1  # q: KERNEL_USER_TIMES
    ThreadPriority = 2  # s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
    ThreadBasePriority = 3  # s: KPRIORITY
    ThreadAffinityMask = 4  # s: KAFFINITY
    ThreadImpersonationToken = 5  # s: HANDLE
    ThreadDescriptorTableEntry = 6  # q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
    ThreadEnableAlignmentFaultFixup = 7  # s: BOOLEAN
    ThreadEventPair = 8
    ThreadQuerySetWin32StartAddress = 9  # q: ULONG_PTR
    ThreadZeroTlsCell = 10  # s: ULONG // TlsIndex // 10
    ThreadPerformanceCount = 11  # q: LARGE_INTEGER
    ThreadAmILastThread = 12  # q: ULONG
    ThreadIdealProcessor = 13  # s: ULONG
    ThreadPriorityBoost = 14  # qs: ULONG
    ThreadSetTlsArrayAddress = 15  # s: ULONG_PTR
    ThreadIsIoPending = 16  # q: ULONG
    ThreadHideFromDebugger = 17  # q: BOOLEAN; s: void
    ThreadBreakOnTermination = 18  # qs: ULONG
    ThreadSwitchLegacyState = 19  # s: void // NtCurrentThread // NPX/FPU
    ThreadIsTerminated = 20  # q: ULONG // 20
    ThreadLastSystemCall = 21  # q: THREAD_LAST_SYSCALL_INFORMATION
    ThreadIoPriority = 22  # qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
    ThreadCycleTime = 23  # q: THREAD_CYCLE_TIME_INFORMATION
    ThreadPagePriority = 24  # qs: PAGE_PRIORITY_INFORMATION
    ThreadActualBasePriority = 25  # s: LONG (requires SeIncreaseBasePriorityPrivilege)
    ThreadTebInformation = 26  # q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
    ThreadCSwitchMon = 27
    ThreadCSwitchPmu = 28
    ThreadWow64Context = 29  # qs: WOW64_CONTEXT
    ThreadGroupInformation = 30  # qs: GROUP_AFFINITY // 30
    ThreadUmsInformation = 31  # q: THREAD_UMS_INFORMATION
    ThreadCounterProfiling = 32  # q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
    ThreadIdealProcessorEx = 33  # qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
    ThreadCpuAccountingInformation = 34  # q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
    ThreadSuspendCount = 35  # q: ULONG // since WINBLUE
    ThreadHeterogeneousCpuPolicy = 36  # q: KHETERO_CPU_POLICY // since THRESHOLD
    ThreadContainerId = 37  # q: GUID
    ThreadNameInformation = 38  # qs: THREAD_NAME_INFORMATION
    ThreadSelectedCpuSets = 39
    ThreadSystemThreadInformation = 40  # q: SYSTEM_THREAD_INFORMATION // 40
    ThreadActualGroupAffinity = 41  # q: GROUP_AFFINITY // since THRESHOLD2
    ThreadDynamicCodePolicyInfo = 42  # q: ULONG; s: ULONG (NtCurrentThread)
    ThreadExplicitCaseSensitivity = 43  # qs: ULONG; s: 0 disables, otherwise enables
    ThreadWorkOnBehalfTicket = 44  # RTL_WORK_ON_BEHALF_TICKET_EX
    ThreadSubsystemInformation = 45  # q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ThreadDbgkWerReportActive = 46  # s: ULONG; s: 0 disables, otherwise enables
    ThreadAttachContainer = 47  # s: HANDLE (job object) // NtCurrentThread
    ThreadManageWritesToExecutableMemory = 48  # MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ThreadPowerThrottlingState = 49  # POWER_THROTTLING_THREAD_STATE
    ThreadWorkloadClass = 50  # THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
    ThreadCreateStateChange = 51  # since WIN11
    ThreadApplyStateChange = 52
    ThreadStrongerBadHandleChecks = 53  # since 22H1
    ThreadEffectiveIoPriority = 54  # q: IO_PRIORITY_HINT
    ThreadEffectivePagePriority = 55  # q: ULONG
    MaxThreadInfoClass = 56

class PROCESS_TLS_INFORMATION_TYPE(Enum):
    ProcessTlsReplaceIndex = 0
    ProcessTlsReplaceVector = 1
    MaxProcessTlsOperation = 2

class PROCESS_WORKING_SET_OPERATION(Enum):
    ProcessWorkingSetSwap = 0
    ProcessWorkingSetEmpty = 1
    ProcessWorkingSetOperationMax = 2

class PS_PROTECTED_TYPE(Enum):
    PsProtectedTypeNone = 0
    PsProtectedTypeProtectedLight = 1
    PsProtectedTypeProtected = 2
    PsProtectedTypeMax = 3

class PS_PROTECTED_SIGNER(Enum):
    PsProtectedSignerNone = 0
    PsProtectedSignerAuthenticode = 1
    PsProtectedSignerCodeGen = 2
    PsProtectedSignerAntimalware = 3
    PsProtectedSignerLsa = 4
    PsProtectedSignerWindows = 5
    PsProtectedSignerWinTcb = 6
    PsProtectedSignerWinSystem = 7
    PsProtectedSignerApp = 8
    PsProtectedSignerMax = 9

class THREAD_UMS_INFORMATION_COMMAND(Enum):
    UmsInformationCommandInvalid = 0
    UmsInformationCommandAttach = 1
    UmsInformationCommandDetach = 2
    UmsInformationCommandQuery = 3

class SUBSYSTEM_INFORMATION_TYPE(Enum):
    SubsystemInformationTypeWin32 = 0
    SubsystemInformationTypeWSL = 1
    MaxSubsystemInformationType = 2

class THREAD_WORKLOAD_CLASS(Enum):
    ThreadWorkloadClassDefault = 0
    ThreadWorkloadClassGraphics = 1
    MaxThreadWorkloadClass = 2

class PROCESS_STATE_CHANGE_TYPE(Enum):
    ProcessStateChangeSuspend = 0
    ProcessStateChangeResume = 1
    ProcessStateChangeMax = 2

class THREAD_STATE_CHANGE_TYPE(Enum):
    ThreadStateChangeSuspend = 0
    ThreadStateChangeResume = 1
    ThreadStateChangeMax = 2

class SE_SAFE_OPEN_PROMPT_EXPERIENCE_RESULTS(Enum):
    SeSafeOpenExperienceNone = 0
    SeSafeOpenExperienceCalled = 1
    SeSafeOpenExperienceAppRepCalled = 2
    SeSafeOpenExperiencePromptDisplayed = 4
    SeSafeOpenExperienceUAC = 8
    SeSafeOpenExperienceUninstaller = 16
    SeSafeOpenExperienceIgnoreUnknownOrBad = 32
    SeSafeOpenExperienceDefenderTrustedInstaller = 64
    SeSafeOpenExperienceMOTWPresent = 128

class PS_ATTRIBUTE_NUM(Enum):
    PsAttributeParentProcess = 0  # in HANDLE
    PsAttributeDebugObject = 1  # in HANDLE
    PsAttributeToken = 2  # in HANDLE
    PsAttributeClientId = 3  # out PCLIENT_ID
    PsAttributeTebAddress = 4  # out PTEB *
    PsAttributeImageName = 5  # in PWSTR
    PsAttributeImageInfo = 6  # out PSECTION_IMAGE_INFORMATION
    PsAttributeMemoryReserve = 7  # in PPS_MEMORY_RESERVE
    PsAttributePriorityClass = 8  # in UCHAR
    PsAttributeErrorMode = 9  # in ULONG
    PsAttributeStdHandleInfo = 10  # 10, in PPS_STD_HANDLE_INFO
    PsAttributeHandleList = 11  # in HANDLE[]
    PsAttributeGroupAffinity = 12  # in PGROUP_AFFINITY
    PsAttributePreferredNode = 13  # in PUSHORT
    PsAttributeIdealProcessor = 14  # in PPROCESSOR_NUMBER
    PsAttributeUmsThread = 15  # ? in PUMS_CREATE_THREAD_ATTRIBUTES
    PsAttributeMitigationOptions = 16  # in PPS_MITIGATION_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_POLICY_*) // since WIN8
    PsAttributeProtectionLevel = 17  # in PS_PROTECTION // since WINBLUE
    PsAttributeSecureProcess = 18  # in PPS_TRUSTLET_CREATE_ATTRIBUTES, since THRESHOLD
    PsAttributeJobList = 19  # in HANDLE[]
    PsAttributeChildProcessPolicy = 20  # 20, in PULONG (PROCESS_CREATION_CHILD_PROCESS_*) // since THRESHOLD2
    PsAttributeAllApplicationPackagesPolicy = 21  # in PULONG (PROCESS_CREATION_ALL_APPLICATION_PACKAGES_*) // since REDSTONE
    PsAttributeWin32kFilter = 22  # in PWIN32K_SYSCALL_FILTER
    PsAttributeSafeOpenPromptOriginClaim = 23  # in
    PsAttributeBnoIsolation = 24  # in PPS_BNO_ISOLATION_PARAMETERS // since REDSTONE2
    PsAttributeDesktopAppPolicy = 25  # in PULONG (PROCESS_CREATION_DESKTOP_APP_*)
    PsAttributeChpe = 26  # in BOOLEAN // since REDSTONE3
    PsAttributeMitigationAuditOptions = 27  # in PPS_MITIGATION_AUDIT_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_AUDIT_POLICY_*) // since 21H1
    PsAttributeMachineType = 28  # in WORD // since 21H2
    PsAttributeComponentFilter = 29
    PsAttributeEnableOptionalXStateFeatures = 30  # since WIN11
    PsAttributeMax = 31

class PS_STD_HANDLE_STATE(Enum):
    PsNeverDuplicate = 0
    PsRequestDuplicate = 1  # duplicate standard handles specified by PseudoHandleMask, and only if StdHandleSubsystemType matches the image subsystem
    PsAlwaysDuplicate = 2  # always duplicate standard handles
    PsMaxStdHandleStates = 3

class PS_MITIGATION_OPTION(Enum):
    PS_MITIGATION_OPTION_NX = 0
    PS_MITIGATION_OPTION_SEHOP = 1
    PS_MITIGATION_OPTION_FORCE_RELOCATE_IMAGES = 2
    PS_MITIGATION_OPTION_HEAP_TERMINATE = 3
    PS_MITIGATION_OPTION_BOTTOM_UP_ASLR = 4
    PS_MITIGATION_OPTION_HIGH_ENTROPY_ASLR = 5
    PS_MITIGATION_OPTION_STRICT_HANDLE_CHECKS = 6
    PS_MITIGATION_OPTION_WIN32K_SYSTEM_CALL_DISABLE = 7
    PS_MITIGATION_OPTION_EXTENSION_POINT_DISABLE = 8
    PS_MITIGATION_OPTION_PROHIBIT_DYNAMIC_CODE = 9
    PS_MITIGATION_OPTION_CONTROL_FLOW_GUARD = 10
    PS_MITIGATION_OPTION_BLOCK_NON_MICROSOFT_BINARIES = 11
    PS_MITIGATION_OPTION_FONT_DISABLE = 12
    PS_MITIGATION_OPTION_IMAGE_LOAD_NO_REMOTE = 13
    PS_MITIGATION_OPTION_IMAGE_LOAD_NO_LOW_LABEL = 14
    PS_MITIGATION_OPTION_IMAGE_LOAD_PREFER_SYSTEM32 = 15
    PS_MITIGATION_OPTION_RETURN_FLOW_GUARD = 16
    PS_MITIGATION_OPTION_LOADER_INTEGRITY_CONTINUITY = 17
    PS_MITIGATION_OPTION_STRICT_CONTROL_FLOW_GUARD = 18
    PS_MITIGATION_OPTION_RESTRICT_SET_THREAD_CONTEXT = 19
    PS_MITIGATION_OPTION_ROP_STACKPIVOT = 20  # since REDSTONE3
    PS_MITIGATION_OPTION_ROP_CALLER_CHECK = 21
    PS_MITIGATION_OPTION_ROP_SIMEXEC = 22
    PS_MITIGATION_OPTION_EXPORT_ADDRESS_FILTER = 23
    PS_MITIGATION_OPTION_EXPORT_ADDRESS_FILTER_PLUS = 24
    PS_MITIGATION_OPTION_RESTRICT_CHILD_PROCESS_CREATION = 25
    PS_MITIGATION_OPTION_IMPORT_ADDRESS_FILTER = 26
    PS_MITIGATION_OPTION_MODULE_TAMPERING_PROTECTION = 27
    PS_MITIGATION_OPTION_RESTRICT_INDIRECT_BRANCH_PREDICTION = 28
    PS_MITIGATION_OPTION_SPECULATIVE_STORE_BYPASS_DISABLE = 29  # since REDSTONE5
    PS_MITIGATION_OPTION_ALLOW_DOWNGRADE_DYNAMIC_CODE_POLICY = 30
    PS_MITIGATION_OPTION_CET_USER_SHADOW_STACKS = 31
    PS_MITIGATION_OPTION_USER_CET_SET_CONTEXT_IP_VALIDATION = 32  # since 21H1
    PS_MITIGATION_OPTION_BLOCK_NON_CET_BINARIES = 33
    PS_MITIGATION_OPTION_CET_DYNAMIC_APIS_OUT_OF_PROC_ONLY = 34
    PS_MITIGATION_OPTION_REDIRECTION_TRUST = 35  # since 22H1

class PS_CREATE_STATE(Enum):
    PsCreateInitialState = 0
    PsCreateFailOnFileOpen = 1
    PsCreateFailOnSectionCreate = 2
    PsCreateFailExeFormat = 3
    PsCreateFailMachineMismatch = 4
    PsCreateFailExeName = 5  # Debugger specified
    PsCreateSuccess = 6
    PsCreateMaximumStates = 7

class MEMORY_RESERVE_TYPE(Enum):
    MemoryReserveUserApc = 0
    MemoryReserveIoCompletion = 1
    MemoryReserveTypeMax = 2

class DBG_STATE(Enum):
    DbgIdle = 0
    DbgReplyPending = 1
    DbgCreateThreadStateChange = 2
    DbgCreateProcessStateChange = 3
    DbgExitThreadStateChange = 4
    DbgExitProcessStateChange = 5
    DbgExceptionStateChange = 6
    DbgBreakpointStateChange = 7
    DbgSingleStepStateChange = 8
    DbgLoadDllStateChange = 9
    DbgUnloadDllStateChange = 10

class DEBUGOBJECTINFOCLASS(Enum):
    DebugObjectUnusedInformation = 0
    DebugObjectKillProcessOnExitInformation = 1  # s: ULONG
    MaxDebugObjectInfoClass = 2

class FILE_INFORMATION_CLASS(Enum):
    FileDirectoryInformation = 1  # FILE_DIRECTORY_INFORMATION
    FileFullDirectoryInformation = 2  # FILE_FULL_DIR_INFORMATION
    FileBothDirectoryInformation = 3  # FILE_BOTH_DIR_INFORMATION
    FileBasicInformation = 4  # FILE_BASIC_INFORMATION
    FileStandardInformation = 5  # FILE_STANDARD_INFORMATION
    FileInternalInformation = 6  # FILE_INTERNAL_INFORMATION
    FileEaInformation = 7  # FILE_EA_INFORMATION
    FileAccessInformation = 8  # FILE_ACCESS_INFORMATION
    FileNameInformation = 9  # FILE_NAME_INFORMATION
    FileRenameInformation = 10  # FILE_RENAME_INFORMATION // 10
    FileLinkInformation = 11  # FILE_LINK_INFORMATION
    FileNamesInformation = 12  # FILE_NAMES_INFORMATION
    FileDispositionInformation = 13  # FILE_DISPOSITION_INFORMATION
    FilePositionInformation = 14  # FILE_POSITION_INFORMATION
    FileFullEaInformation = 15  # FILE_FULL_EA_INFORMATION
    FileModeInformation = 16  # FILE_MODE_INFORMATION
    FileAlignmentInformation = 17  # FILE_ALIGNMENT_INFORMATION
    FileAllInformation = 18  # FILE_ALL_INFORMATION
    FileAllocationInformation = 19  # FILE_ALLOCATION_INFORMATION
    FileEndOfFileInformation = 20  # FILE_END_OF_FILE_INFORMATION // 20
    FileAlternateNameInformation = 21  # FILE_NAME_INFORMATION
    FileStreamInformation = 22  # FILE_STREAM_INFORMATION
    FilePipeInformation = 23  # FILE_PIPE_INFORMATION
    FilePipeLocalInformation = 24  # FILE_PIPE_LOCAL_INFORMATION
    FilePipeRemoteInformation = 25  # FILE_PIPE_REMOTE_INFORMATION
    FileMailslotQueryInformation = 26  # FILE_MAILSLOT_QUERY_INFORMATION
    FileMailslotSetInformation = 27  # FILE_MAILSLOT_SET_INFORMATION
    FileCompressionInformation = 28  # FILE_COMPRESSION_INFORMATION
    FileObjectIdInformation = 29  # FILE_OBJECTID_INFORMATION
    FileCompletionInformation = 30  # FILE_COMPLETION_INFORMATION // 30
    FileMoveClusterInformation = 31  # FILE_MOVE_CLUSTER_INFORMATION
    FileQuotaInformation = 32  # FILE_QUOTA_INFORMATION
    FileReparsePointInformation = 33  # FILE_REPARSE_POINT_INFORMATION
    FileNetworkOpenInformation = 34  # FILE_NETWORK_OPEN_INFORMATION
    FileAttributeTagInformation = 35  # FILE_ATTRIBUTE_TAG_INFORMATION
    FileTrackingInformation = 36  # FILE_TRACKING_INFORMATION
    FileIdBothDirectoryInformation = 37  # FILE_ID_BOTH_DIR_INFORMATION
    FileIdFullDirectoryInformation = 38  # FILE_ID_FULL_DIR_INFORMATION
    FileValidDataLengthInformation = 39  # FILE_VALID_DATA_LENGTH_INFORMATION
    FileShortNameInformation = 40  # FILE_NAME_INFORMATION // 40
    FileIoCompletionNotificationInformation = 41  # FILE_IO_COMPLETION_NOTIFICATION_INFORMATION // since VISTA
    FileIoStatusBlockRangeInformation = 42  # FILE_IOSTATUSBLOCK_RANGE_INFORMATION
    FileIoPriorityHintInformation = 43  # FILE_IO_PRIORITY_HINT_INFORMATION, FILE_IO_PRIORITY_HINT_INFORMATION_EX
    FileSfioReserveInformation = 44  # FILE_SFIO_RESERVE_INFORMATION
    FileSfioVolumeInformation = 45  # FILE_SFIO_VOLUME_INFORMATION
    FileHardLinkInformation = 46  # FILE_LINKS_INFORMATION
    FileProcessIdsUsingFileInformation = 47  # FILE_PROCESS_IDS_USING_FILE_INFORMATION
    FileNormalizedNameInformation = 48  # FILE_NAME_INFORMATION
    FileNetworkPhysicalNameInformation = 49  # FILE_NETWORK_PHYSICAL_NAME_INFORMATION
    FileIdGlobalTxDirectoryInformation = 50  # FILE_ID_GLOBAL_TX_DIR_INFORMATION // since WIN7 // 50
    FileIsRemoteDeviceInformation = 51  # FILE_IS_REMOTE_DEVICE_INFORMATION
    FileUnusedInformation = 52
    FileNumaNodeInformation = 53  # FILE_NUMA_NODE_INFORMATION
    FileStandardLinkInformation = 54  # FILE_STANDARD_LINK_INFORMATION
    FileRemoteProtocolInformation = 55  # FILE_REMOTE_PROTOCOL_INFORMATION
    FileRenameInformationBypassAccessCheck = 56  # (kernel-mode only); FILE_RENAME_INFORMATION // since WIN8
    FileLinkInformationBypassAccessCheck = 57  # (kernel-mode only); FILE_LINK_INFORMATION
    FileVolumeNameInformation = 58  # FILE_VOLUME_NAME_INFORMATION
    FileIdInformation = 59  # FILE_ID_INFORMATION
    FileIdExtdDirectoryInformation = 60  # FILE_ID_EXTD_DIR_INFORMATION // 60
    FileReplaceCompletionInformation = 61  # FILE_COMPLETION_INFORMATION // since WINBLUE
    FileHardLinkFullIdInformation = 62  # FILE_LINK_ENTRY_FULL_ID_INFORMATION // FILE_LINKS_FULL_ID_INFORMATION
    FileIdExtdBothDirectoryInformation = 63  # FILE_ID_EXTD_BOTH_DIR_INFORMATION // since THRESHOLD
    FileDispositionInformationEx = 64  # FILE_DISPOSITION_INFO_EX // since REDSTONE
    FileRenameInformationEx = 65  # FILE_RENAME_INFORMATION_EX
    FileRenameInformationExBypassAccessCheck = 66  # (kernel-mode only); FILE_RENAME_INFORMATION_EX
    FileDesiredStorageClassInformation = 67  # FILE_DESIRED_STORAGE_CLASS_INFORMATION // since REDSTONE2
    FileStatInformation = 68  # FILE_STAT_INFORMATION
    FileMemoryPartitionInformation = 69  # FILE_MEMORY_PARTITION_INFORMATION // since REDSTONE3
    FileStatLxInformation = 70  # FILE_STAT_LX_INFORMATION // since REDSTONE4 // 70
    FileCaseSensitiveInformation = 71  # FILE_CASE_SENSITIVE_INFORMATION
    FileLinkInformationEx = 72  # FILE_LINK_INFORMATION_EX // since REDSTONE5
    FileLinkInformationExBypassAccessCheck = 73  # (kernel-mode only); FILE_LINK_INFORMATION_EX
    FileStorageReserveIdInformation = 74  # FILE_SET_STORAGE_RESERVE_ID_INFORMATION
    FileCaseSensitiveInformationForceAccessCheck = 75  # FILE_CASE_SENSITIVE_INFORMATION
    FileKnownFolderInformation = 76  # FILE_KNOWN_FOLDER_INFORMATION // since WIN11
    FileMaximumInformation = 77

class IO_PRIORITY_HINT(Enum):
    IoPriorityVeryLow = 0  # Defragging, content indexing and other background I/Os.
    IoPriorityLow = 1  # Prefetching for applications.
    IoPriorityNormal = 2  # Normal I/Os.
    IoPriorityHigh = 3  # Used by filesystems for checkpoint I/O.
    IoPriorityCritical = 4  # Used by memory manager. Not available for applications.
    MaxIoPriorityTypes = 5

class FILE_KNOWN_FOLDER_TYPE(Enum):
    KnownFolderNone = 0
    KnownFolderDesktop = 1
    KnownFolderDocuments = 2
    KnownFolderDownloads = 3
    KnownFolderMusic = 4
    KnownFolderPictures = 5
    KnownFolderVideos = 6
    KnownFolderOther = 7
    KnownFolderMax = 7

class FSINFOCLASS(Enum):
    FileFsVolumeInformation = 1  # FILE_FS_VOLUME_INFORMATION
    FileFsLabelInformation = 2  # FILE_FS_LABEL_INFORMATION
    FileFsSizeInformation = 3  # FILE_FS_SIZE_INFORMATION
    FileFsDeviceInformation = 4  # FILE_FS_DEVICE_INFORMATION
    FileFsAttributeInformation = 5  # FILE_FS_ATTRIBUTE_INFORMATION
    FileFsControlInformation = 6  # FILE_FS_CONTROL_INFORMATION
    FileFsFullSizeInformation = 7  # FILE_FS_FULL_SIZE_INFORMATION
    FileFsObjectIdInformation = 8  # FILE_FS_OBJECTID_INFORMATION
    FileFsDriverPathInformation = 9  # FILE_FS_DRIVER_PATH_INFORMATION
    FileFsVolumeFlagsInformation = 10  # FILE_FS_VOLUME_FLAGS_INFORMATION // 10
    FileFsSectorSizeInformation = 11  # FILE_FS_SECTOR_SIZE_INFORMATION // since WIN8
    FileFsDataCopyInformation = 12  # FILE_FS_DATA_COPY_INFORMATION
    FileFsMetadataSizeInformation = 13  # FILE_FS_METADATA_SIZE_INFORMATION // since THRESHOLD
    FileFsFullSizeInformationEx = 14  # FILE_FS_FULL_SIZE_INFORMATION_EX // since REDSTONE5
    FileFsMaximumInformation = 15

class DIRECTORY_NOTIFY_INFORMATION_CLASS(Enum):
    DirectoryNotifyInformation = 1  # FILE_NOTIFY_INFORMATION
    DirectoryNotifyExtendedInformation = 2  # FILE_NOTIFY_EXTENDED_INFORMATION
    DirectoryNotifyFullInformation = 3  # since 22H2
    DirectoryNotifyMaximumInformation = 4

class IO_COMPLETION_INFORMATION_CLASS(Enum):
    IoCompletionBasicInformation = 0

class IO_SESSION_EVENT(Enum):
    IoSessionEventIgnore = 0
    IoSessionEventCreated = 1
    IoSessionEventTerminated = 2
    IoSessionEventConnected = 3
    IoSessionEventDisconnected = 4
    IoSessionEventLogon = 5
    IoSessionEventLogoff = 6
    IoSessionEventMax = 7

class IO_SESSION_STATE(Enum):
    IoSessionStateCreated = 1
    IoSessionStateInitialized = 2
    IoSessionStateConnected = 3
    IoSessionStateDisconnected = 4
    IoSessionStateDisconnectedLoggedOn = 5
    IoSessionStateLoggedOn = 6
    IoSessionStateLoggedOff = 7
    IoSessionStateTerminated = 8
    IoSessionStateMax = 9

class INTERFACE_TYPE(Enum):
    InterfaceTypeUndefined = -1
    Internal = 0
    Isa = 1
    Eisa = 2
    MicroChannel = 3
    TurboChannel = 4
    PCIBus = 5
    VMEBus = 6
    NuBus = 7
    PCMCIABus = 8
    CBus = 9
    MPIBus = 10
    MPSABus = 11
    ProcessorInternal = 12
    InternalPowerBus = 13
    PNPISABus = 14
    PNPBus = 15
    Vmcs = 16
    ACPIBus = 17
    MaximumInterfaceType = 18

class DMA_WIDTH(Enum):
    Width8Bits = 0
    Width16Bits = 1
    Width32Bits = 2
    Width64Bits = 3
    WidthNoWrap = 4
    MaximumDmaWidth = 5

class DMA_SPEED(Enum):
    Compatible = 0
    TypeA = 1
    TypeB = 2
    TypeC = 3
    TypeF = 4
    MaximumDmaSpeed = 5

class BUS_DATA_TYPE(Enum):
    ConfigurationSpaceUndefined = -1
    Cmos = 0
    EisaConfiguration = 1
    Pos = 2
    CbusConfiguration = 3
    PCIConfiguration = 4
    VMEConfiguration = 5
    NuBusConfiguration = 6
    PCMCIAConfiguration = 7
    MPIConfiguration = 8
    MPSAConfiguration = 9
    PNPISAConfiguration = 10
    SgiInternalConfiguration = 11
    MaximumBusDataType = 12

class PORT_INFORMATION_CLASS(Enum):
    PortBasicInformation = 0
    PortDumpInformation = 1

class ALPC_PORT_INFORMATION_CLASS(Enum):
    AlpcBasicInformation = 0  # q: out ALPC_BASIC_INFORMATION
    AlpcPortInformation = 1  # s: in ALPC_PORT_ATTRIBUTES
    AlpcAssociateCompletionPortInformation = 2  # s: in ALPC_PORT_ASSOCIATE_COMPLETION_PORT
    AlpcConnectedSIDInformation = 3  # q: in SID
    AlpcServerInformation = 4  # q: inout ALPC_SERVER_INFORMATION
    AlpcMessageZoneInformation = 5  # s: in ALPC_PORT_MESSAGE_ZONE_INFORMATION
    AlpcRegisterCompletionListInformation = 6  # s: in ALPC_PORT_COMPLETION_LIST_INFORMATION
    AlpcUnregisterCompletionListInformation = 7  # s: VOID
    AlpcAdjustCompletionListConcurrencyCountInformation = 8  # s: in ULONG
    AlpcRegisterCallbackInformation = 9  # kernel-mode only
    AlpcCompletionListRundownInformation = 10  # s: VOID // 10
    AlpcWaitForPortReferences = 11
    AlpcServerSessionInformation = 12  # q: ALPC_SERVER_SESSION_INFORMATION // since 19H2

class ALPC_MESSAGE_INFORMATION_CLASS(Enum):
    AlpcMessageSidInformation = 0  # q: out SID
    AlpcMessageTokenModifiedIdInformation = 1  # q: out LUID
    AlpcMessageDirectStatusInformation = 2
    AlpcMessageHandleInformation = 3  # ALPC_MESSAGE_HANDLE_INFORMATION
    MaxAlpcMessageInfoClass = 4

class PF_BOOT_PHASE_ID(Enum):
    PfKernelInitPhase = 0
    PfBootDriverInitPhase = 90
    PfSystemDriverInitPhase = 120
    PfSessionManagerInitPhase = 150
    PfSMRegistryInitPhase = 180
    PfVideoInitPhase = 210
    PfPostVideoInitPhase = 240
    PfBootAcceptedRegistryInitPhase = 270
    PfUserShellReadyPhase = 300
    PfMaxBootPhaseId = 900

class PF_ENABLE_STATUS(Enum):
    PfSvNotSpecified = 0
    PfSvEnabled = 1
    PfSvDisabled = 2
    PfSvMaxEnableStatus = 3

class PREFETCHER_INFORMATION_CLASS(Enum):
    PrefetcherRetrieveTrace = 1  # q: CHAR[]
    PrefetcherSystemParameters = 2  # q: PF_SYSTEM_PREFETCH_PARAMETERS
    PrefetcherBootPhase = 3  # s: PF_BOOT_PHASE_ID
    PrefetcherSpare1 = 4  # PrefetcherRetrieveBootLoaderTrace // q: CHAR[]
    PrefetcherBootControl = 5  # s: PF_BOOT_CONTROL
    PrefetcherScenarioPolicyControl = 6
    PrefetcherSpare2 = 7
    PrefetcherAppLaunchScenarioControl = 8
    PrefetcherInformationMax = 9

class PFS_PRIVATE_PAGE_SOURCE_TYPE(Enum):
    PfsPrivateSourceKernel = 0
    PfsPrivateSourceSession = 1
    PfsPrivateSourceProcess = 2
    PfsPrivateSourceMax = 3

class PF_PHASED_SCENARIO_TYPE(Enum):
    PfScenarioTypeNone = 0
    PfScenarioTypeStandby = 1
    PfScenarioTypeHibernate = 2
    PfScenarioTypeFUS = 3
    PfScenarioTypeMax = 4

class SUPERFETCH_INFORMATION_CLASS(Enum):
    SuperfetchRetrieveTrace = 1  # q: CHAR[]
    SuperfetchSystemParameters = 2  # q: PF_SYSTEM_SUPERFETCH_PARAMETERS
    SuperfetchLogEvent = 3
    SuperfetchGenerateTrace = 4
    SuperfetchPrefetch = 5
    SuperfetchPfnQuery = 6  # q: PF_PFN_PRIO_REQUEST
    SuperfetchPfnSetPriority = 7
    SuperfetchPrivSourceQuery = 8  # q: PF_PRIVSOURCE_QUERY_REQUEST
    SuperfetchSequenceNumberQuery = 9  # q: ULONG
    SuperfetchScenarioPhase = 10  # 10
    SuperfetchWorkerPriority = 11
    SuperfetchScenarioQuery = 12  # q: PF_SCENARIO_PHASE_INFO
    SuperfetchScenarioPrefetch = 13
    SuperfetchRobustnessControl = 14
    SuperfetchTimeControl = 15
    SuperfetchMemoryListQuery = 16  # q: PF_MEMORY_LIST_INFO
    SuperfetchMemoryRangesQuery = 17  # q: PF_PHYSICAL_MEMORY_RANGE_INFO
    SuperfetchTracingControl = 18
    SuperfetchTrimWhileAgingControl = 19
    SuperfetchRepurposedByPrefetch = 20  # q: PF_REPURPOSED_BY_PREFETCH_INFO // rev
    SuperfetchChannelPowerRequest = 21
    SuperfetchMovePages = 22
    SuperfetchVirtualQuery = 23
    SuperfetchCombineStatsQuery = 24
    SuperfetchSetMinWsAgeRate = 25
    SuperfetchDeprioritizeOldPagesInWs = 26
    SuperfetchFileExtentsQuery = 27
    SuperfetchGpuUtilizationQuery = 28  # PF_GPU_UTILIZATION_INFO
    SuperfetchInformationMax = 29

class PLUGPLAY_EVENT_CATEGORY(Enum):
    HardwareProfileChangeEvent = 0
    TargetDeviceChangeEvent = 1
    DeviceClassChangeEvent = 2
    CustomDeviceEvent = 3
    DeviceInstallEvent = 4
    DeviceArrivalEvent = 5
    PowerEvent = 6
    VetoEvent = 7
    BlockedDriverEvent = 8
    InvalidIDEvent = 9
    MaxPlugEventCategory = 10

class PLUGPLAY_CONTROL_CLASS(Enum):
    PlugPlayControlEnumerateDevice = 0  # PLUGPLAY_CONTROL_ENUMERATE_DEVICE_DATA
    PlugPlayControlRegisterNewDevice = 1  # PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA
    PlugPlayControlDeregisterDevice = 2  # PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA
    PlugPlayControlInitializeDevice = 3  # PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA
    PlugPlayControlStartDevice = 4  # PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA
    PlugPlayControlUnlockDevice = 5  # PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA
    PlugPlayControlQueryAndRemoveDevice = 6  # PLUGPLAY_CONTROL_QUERY_AND_REMOVE_DATA
    PlugPlayControlUserResponse = 7  # PLUGPLAY_CONTROL_USER_RESPONSE_DATA
    PlugPlayControlGenerateLegacyDevice = 8  # PLUGPLAY_CONTROL_LEGACY_DEVGEN_DATA
    PlugPlayControlGetInterfaceDeviceList = 9  # PLUGPLAY_CONTROL_INTERFACE_LIST_DATA
    PlugPlayControlProperty = 10  # PLUGPLAY_CONTROL_PROPERTY_DATA
    PlugPlayControlDeviceClassAssociation = 11  # PLUGPLAY_CONTROL_CLASS_ASSOCIATION_DATA
    PlugPlayControlGetRelatedDevice = 12  # PLUGPLAY_CONTROL_RELATED_DEVICE_DATA
    PlugPlayControlGetInterfaceDeviceAlias = 13  # PLUGPLAY_CONTROL_INTERFACE_ALIAS_DATA
    PlugPlayControlDeviceStatus = 14  # PLUGPLAY_CONTROL_STATUS_DATA
    PlugPlayControlGetDeviceDepth = 15  # PLUGPLAY_CONTROL_DEPTH_DATA
    PlugPlayControlQueryDeviceRelations = 16  # PLUGPLAY_CONTROL_DEVICE_RELATIONS_DATA
    PlugPlayControlTargetDeviceRelation = 17  # PLUGPLAY_CONTROL_TARGET_RELATION_DATA
    PlugPlayControlQueryConflictList = 18  # PLUGPLAY_CONTROL_CONFLICT_LIST
    PlugPlayControlRetrieveDock = 19  # PLUGPLAY_CONTROL_RETRIEVE_DOCK_DATA
    PlugPlayControlResetDevice = 20  # PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA
    PlugPlayControlHaltDevice = 21  # PLUGPLAY_CONTROL_DEVICE_CONTROL_DATA
    PlugPlayControlGetBlockedDriverList = 22  # PLUGPLAY_CONTROL_BLOCKED_DRIVER_DATA
    PlugPlayControlGetDeviceInterfaceEnabled = 23  # PLUGPLAY_CONTROL_DEVICE_INTERFACE_ENABLED
    MaxPlugPlayControl = 24

class POWER_REQUEST_TYPE_INTERNAL(Enum):
    PowerRequestDisplayRequiredInternal = 0
    PowerRequestSystemRequiredInternal = 1
    PowerRequestAwayModeRequiredInternal = 2
    PowerRequestExecutionRequiredInternal = 3  # Windows 8+
    PowerRequestPerfBoostRequiredInternal = 4  # Windows 8+
    PowerRequestActiveLockScreenInternal = 5  # Windows 10 RS1+ (reserved on Windows 8)
    PowerRequestInternalInvalid = 6
    PowerRequestInternalUnknown = 7
    PowerRequestFullScreenVideoRequired = 8  # Windows 8 only

class POWER_STATE_TYPE(Enum):
    SystemPowerState = 0
    DevicePowerState = 1

class REQUESTER_TYPE(Enum):
    KernelRequester = 0
    UserProcessRequester = 1
    UserSharedServiceRequester = 2

class POWER_STATE_HANDLER_TYPE(Enum):
    PowerStateSleeping1 = 0
    PowerStateSleeping2 = 1
    PowerStateSleeping3 = 2
    PowerStateSleeping4 = 3
    PowerStateShutdownOff = 4
    PowerStateShutdownReset = 5
    PowerStateSleeping4Firmware = 6
    PowerStateMaximum = 7

class POWER_INFORMATION_LEVEL_INTERNAL(Enum):
    PowerInternalAcpiInterfaceRegister = 0
    PowerInternalS0LowPowerIdleInfo = 1  # POWER_S0_LOW_POWER_IDLE_INFO
    PowerInternalReapplyBrightnessSettings = 2
    PowerInternalUserAbsencePrediction = 3  # POWER_USER_ABSENCE_PREDICTION
    PowerInternalUserAbsencePredictionCapability = 4  # POWER_USER_ABSENCE_PREDICTION_CAPABILITY
    PowerInternalPoProcessorLatencyHint = 5  # POWER_PROCESSOR_LATENCY_HINT
    PowerInternalStandbyNetworkRequest = 6  # POWER_STANDBY_NETWORK_REQUEST
    PowerInternalDirtyTransitionInformation = 7
    PowerInternalSetBackgroundTaskState = 8  # POWER_SET_BACKGROUND_TASK_STATE
    PowerInternalTtmOpenTerminal = 9
    PowerInternalTtmCreateTerminal = 10  # 10
    PowerInternalTtmEvacuateDevices = 11
    PowerInternalTtmCreateTerminalEventQueue = 12
    PowerInternalTtmGetTerminalEvent = 13
    PowerInternalTtmSetDefaultDeviceAssignment = 14
    PowerInternalTtmAssignDevice = 15
    PowerInternalTtmSetDisplayState = 16
    PowerInternalTtmSetDisplayTimeouts = 17
    PowerInternalBootSessionStandbyActivationInformation = 18
    PowerInternalSessionPowerState = 19
    PowerInternalSessionTerminalInput = 20  # 20
    PowerInternalSetWatchdog = 21
    PowerInternalPhysicalPowerButtonPressInfoAtBoot = 22
    PowerInternalExternalMonitorConnected = 23
    PowerInternalHighPrecisionBrightnessSettings = 24
    PowerInternalWinrtScreenToggle = 25
    PowerInternalPpmQosDisable = 26
    PowerInternalTransitionCheckpoint = 27
    PowerInternalInputControllerState = 28
    PowerInternalFirmwareResetReason = 29
    PowerInternalPpmSchedulerQosSupport = 30  # 30
    PowerInternalBootStatGet = 31
    PowerInternalBootStatSet = 32
    PowerInternalCallHasNotReturnedWatchdog = 33
    PowerInternalBootStatCheckIntegrity = 34
    PowerInternalBootStatRestoreDefaults = 35  # in: void
    PowerInternalHostEsStateUpdate = 36
    PowerInternalGetPowerActionState = 37
    PowerInternalBootStatUnlock = 38
    PowerInternalWakeOnVoiceState = 39
    PowerInternalDeepSleepBlock = 40  # 40
    PowerInternalIsPoFxDevice = 41
    PowerInternalPowerTransitionExtensionAtBoot = 42
    PowerInternalProcessorBrandedFrequency = 43  # in: POWER_INTERNAL_PROCESSOR_BRANDED_FREQENCY_INPUT, out: POWER_INTERNAL_PROCESSOR_BRANDED_FREQENCY_OUTPUT
    PowerInternalTimeBrokerExpirationReason = 44
    PowerInternalNotifyUserShutdownStatus = 45
    PowerInternalPowerRequestTerminalCoreWindow = 46
    PowerInternalProcessorIdleVeto = 47
    PowerInternalPlatformIdleVeto = 48
    PowerInternalIsLongPowerButtonBugcheckEnabled = 49
    PowerInternalAutoChkCausedReboot = 50  # 50
    PowerInternalSetWakeAlarmOverride = 51
    PowerInternalDirectedFxAddTestDevice = 53
    PowerInternalDirectedFxRemoveTestDevice = 54
    PowerInternalDirectedFxSetMode = 56
    PowerInternalRegisterPowerPlane = 57
    PowerInternalSetDirectedDripsFlags = 58
    PowerInternalClearDirectedDripsFlags = 59
    PowerInternalRetrieveHiberFileResumeContext = 60  # 60
    PowerInternalReadHiberFilePage = 61
    PowerInternalLastBootSucceeded = 62  # out: BOOLEAN
    PowerInternalQuerySleepStudyHelperRoutineBlock = 63
    PowerInternalDirectedDripsQueryCapabilities = 64
    PowerInternalClearConstraints = 65
    PowerInternalSoftParkVelocityEnabled = 66
    PowerInternalQueryIntelPepCapabilities = 67
    PowerInternalGetSystemIdleLoopEnablement = 68  # since WIN11
    PowerInternalGetVmPerfControlSupport = 69
    PowerInternalGetVmPerfControlConfig = 70  # 70
    PowerInternalSleepDetailedDiagUpdate = 71
    PowerInternalProcessorClassFrequencyBandsStats = 72
    PowerInternalHostGlobalUserPresenceStateUpdate = 73
    PowerInternalCpuNodeIdleIntervalStats = 74
    PowerInternalClassIdleIntervalStats = 75
    PowerInternalCpuNodeConcurrencyStats = 76
    PowerInternalClassConcurrencyStats = 77
    PowerInternalQueryProcMeasurementCapabilities = 78
    PowerInternalQueryProcMeasurementValues = 79
    PowerInternalPrepareForSystemInitiatedReboot = 80  # 80
    PowerInternalGetAdaptiveSessionState = 81
    PowerInternalSetConsoleLockedState = 82
    PowerInternalOverrideSystemInitiatedRebootState = 83
    PowerInternalFanImpactStats = 84
    PowerInternalFanRpmBuckets = 85
    PowerInternalPowerBootAppDiagInfo = 86
    PowerInternalUnregisterShutdownNotification = 87  # since 22H1
    PowerInternalManageTransitionStateRecord = 88
    PowerInformationInternalMaximum = 89

class POWER_S0_DISCONNECTED_REASON(Enum):
    PoS0DisconnectedReasonNone = 0
    PoS0DisconnectedReasonNonCompliantNic = 1
    PoS0DisconnectedReasonSettingPolicy = 2
    PoS0DisconnectedReasonEnforceDsPolicy = 3
    PoS0DisconnectedReasonCsChecksFailed = 4
    PoS0DisconnectedReasonSmartStandby = 5
    PoS0DisconnectedReasonMaximum = 6

class KEY_INFORMATION_CLASS(Enum):
    KeyBasicInformation = 0  # KEY_BASIC_INFORMATION
    KeyNodeInformation = 1  # KEY_NODE_INFORMATION
    KeyFullInformation = 2  # KEY_FULL_INFORMATION
    KeyNameInformation = 3  # KEY_NAME_INFORMATION
    KeyCachedInformation = 4  # KEY_CACHED_INFORMATION
    KeyFlagsInformation = 5  # KEY_FLAGS_INFORMATION
    KeyVirtualizationInformation = 6  # KEY_VIRTUALIZATION_INFORMATION
    KeyHandleTagsInformation = 7  # KEY_HANDLE_TAGS_INFORMATION
    KeyTrustInformation = 8  # KEY_TRUST_INFORMATION
    KeyLayerInformation = 9  # KEY_LAYER_INFORMATION
    MaxKeyInfoClass = 10

class KEY_SET_INFORMATION_CLASS(Enum):
    KeyWriteTimeInformation = 0  # KEY_WRITE_TIME_INFORMATION
    KeyWow64FlagsInformation = 1  # KEY_WOW64_FLAGS_INFORMATION
    KeyControlFlagsInformation = 2  # KEY_CONTROL_FLAGS_INFORMATION
    KeySetVirtualizationInformation = 3  # KEY_SET_VIRTUALIZATION_INFORMATION
    KeySetDebugInformation = 4
    KeySetHandleTagsInformation = 5  # KEY_HANDLE_TAGS_INFORMATION
    KeySetLayerInformation = 6  # KEY_SET_LAYER_INFORMATION
    MaxKeySetInfoClass = 7

class KEY_VALUE_INFORMATION_CLASS(Enum):
    KeyValueBasicInformation = 0  # KEY_VALUE_BASIC_INFORMATION
    KeyValueFullInformation = 1  # KEY_VALUE_FULL_INFORMATION
    KeyValuePartialInformation = 2  # KEY_VALUE_PARTIAL_INFORMATION
    KeyValueFullInformationAlign64 = 3
    KeyValuePartialInformationAlign64 = 4  # KEY_VALUE_PARTIAL_INFORMATION_ALIGN64
    KeyValueLayerInformation = 5  # KEY_VALUE_LAYER_INFORMATION
    MaxKeyValueInfoClass = 6

class KEY_LOAD_ENTRY_TYPE(Enum):
    KeyLoadTrustClassKey = 1
    KeyLoadEvent = 2
    KeyLoadToken = 3

class REG_ACTION(Enum):
    KeyAdded = 0
    KeyRemoved = 1
    KeyModified = 2

class TABLE_SEARCH_RESULT(Enum):
    TableEmptyTree = 0
    TableFoundNode = 1
    TableInsertAsLeft = 2
    TableInsertAsRight = 3

class RTL_GENERIC_COMPARE_RESULTS(Enum):
    GenericLessThan = 0
    GenericGreaterThan = 1
    GenericEqual = 2

class RTL_NORM_FORM(Enum):
    NormOther = 0
    NormC = 1
    NormD = 2
    NormKC = 5
    NormKD = 6
    NormIdna = 13
    DisallowUnassigned = 256
    NormCDisallowUnassigned = 257
    NormDDisallowUnassigned = 258
    NormKCDisallowUnassigned = 261
    NormKDDisallowUnassigned = 262
    NormIdnaDisallowUnassigned = 269

class FUNCTION_TABLE_TYPE(Enum):
    RF_SORTED = 0
    RF_UNSORTED = 1
    RF_CALLBACK = 2
    RF_KERNEL_DYNAMIC = 3

class RTL_PATH_TYPE(Enum):
    RtlPathTypeUnknown = 0
    RtlPathTypeUncAbsolute = 1
    RtlPathTypeDriveAbsolute = 2
    RtlPathTypeDriveRelative = 3
    RtlPathTypeRooted = 4
    RtlPathTypeRelative = 5
    RtlPathTypeLocalDevice = 6
    RtlPathTypeRootLocalDevice = 7

class HEAP_COMPATIBILITY_MODE(Enum):
    HEAP_COMPATIBILITY_STANDARD = 0
    HEAP_COMPATIBILITY_LAL = 1
    HEAP_COMPATIBILITY_LFH = 2

class IMAGE_MITIGATION_POLICY(Enum):
    ImageDepPolicy = 0  # RTL_IMAGE_MITIGATION_DEP_POLICY
    ImageAslrPolicy = 1  # RTL_IMAGE_MITIGATION_ASLR_POLICY
    ImageDynamicCodePolicy = 2  # RTL_IMAGE_MITIGATION_DYNAMIC_CODE_POLICY
    ImageStrictHandleCheckPolicy = 3  # RTL_IMAGE_MITIGATION_STRICT_HANDLE_CHECK_POLICY
    ImageSystemCallDisablePolicy = 4  # RTL_IMAGE_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
    ImageMitigationOptionsMask = 5
    ImageExtensionPointDisablePolicy = 6  # RTL_IMAGE_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
    ImageControlFlowGuardPolicy = 7  # RTL_IMAGE_MITIGATION_CONTROL_FLOW_GUARD_POLICY
    ImageSignaturePolicy = 8  # RTL_IMAGE_MITIGATION_BINARY_SIGNATURE_POLICY
    ImageFontDisablePolicy = 9  # RTL_IMAGE_MITIGATION_FONT_DISABLE_POLICY
    ImageImageLoadPolicy = 10  # RTL_IMAGE_MITIGATION_IMAGE_LOAD_POLICY
    ImagePayloadRestrictionPolicy = 11  # RTL_IMAGE_MITIGATION_PAYLOAD_RESTRICTION_POLICY
    ImageChildProcessPolicy = 12  # RTL_IMAGE_MITIGATION_CHILD_PROCESS_POLICY
    ImageSehopPolicy = 13  # RTL_IMAGE_MITIGATION_SEHOP_POLICY
    ImageHeapPolicy = 14  # RTL_IMAGE_MITIGATION_HEAP_POLICY
    ImageUserShadowStackPolicy = 15  # RTL_IMAGE_MITIGATION_USER_SHADOW_STACK_POLICY
    MaxImageMitigationPolicy = 16

class RTL_IMAGE_MITIGATION_OPTION_STATE(Enum):
    RtlMitigationOptionStateNotConfigured = 0
    RtlMitigationOptionStateOn = 1
    RtlMitigationOptionStateOff = 2
    RtlMitigationOptionStateForce = 3
    RtlMitigationOptionStateOption = 4

class APPCONTAINER_SID_TYPE(Enum):
    NotAppContainerSidType = 0
    ChildAppContainerSidType = 1
    ParentAppContainerSidType = 2
    InvalidAppContainerSidType = 3
    MaxAppContainerSidType = 4

class STATE_LOCATION_TYPE(Enum):
    LocationTypeRegistry = 0
    LocationTypeFileSystem = 1
    LocationTypeMaximum = 2

class RTL_BSD_ITEM_TYPE(Enum):
    RtlBsdItemVersionNumber = 0  # q; s: ULONG
    RtlBsdItemProductType = 1  # q; s: NT_PRODUCT_TYPE (ULONG)
    RtlBsdItemAabEnabled = 2  # q: s: BOOLEAN // AutoAdvancedBoot
    RtlBsdItemAabTimeout = 3  # q: s: UCHAR // AdvancedBootMenuTimeout
    RtlBsdItemBootGood = 4  # q: s: BOOLEAN // LastBootSucceeded
    RtlBsdItemBootShutdown = 5  # q: s: BOOLEAN // LastBootShutdown
    RtlBsdSleepInProgress = 6  # q: s: BOOLEAN // SleepInProgress
    RtlBsdPowerTransition = 7  # q: s: RTL_BSD_DATA_POWER_TRANSITION
    RtlBsdItemBootAttemptCount = 8  # q: s: UCHAR // BootAttemptCount
    RtlBsdItemBootCheckpoint = 9  # q: s: UCHAR // LastBootCheckpoint
    RtlBsdItemBootId = 10  # q; s: ULONG (USER_SHARED_DATA->BootId)
    RtlBsdItemShutdownBootId = 11  # q; s: ULONG
    RtlBsdItemReportedAbnormalShutdownBootId = 12  # q; s: ULONG
    RtlBsdItemErrorInfo = 13  # RTL_BSD_DATA_ERROR_INFO
    RtlBsdItemPowerButtonPressInfo = 14  # RTL_BSD_POWER_BUTTON_PRESS_INFO
    RtlBsdItemChecksum = 15  # q: s: UCHAR
    RtlBsdPowerTransitionExtension = 16
    RtlBsdItemFeatureConfigurationState = 17  # q; s: ULONG
    RtlBsdItemMax = 18

class TOKEN_SECURITY_ATTRIBUTE_OPERATION(Enum):
    TOKEN_SECURITY_ATTRIBUTE_OPERATION_NONE = 0
    TOKEN_SECURITY_ATTRIBUTE_OPERATION_REPLACE_ALL = 1
    TOKEN_SECURITY_ATTRIBUTE_OPERATION_ADD = 2
    TOKEN_SECURITY_ATTRIBUTE_OPERATION_DELETE = 3
    TOKEN_SECURITY_ATTRIBUTE_OPERATION_REPLACE = 4

class TP_TRACE_TYPE(Enum):
    TpTraceThreadPriority = 1
    TpTraceThreadAffinity = 2
    MaxTpTraceType = 3

class WOW64_SHARED_INFORMATION(Enum):
    SharedNtdll32LdrInitializeThunk = 0
    SharedNtdll32KiUserExceptionDispatcher = 1
    SharedNtdll32KiUserApcDispatcher = 2
    SharedNtdll32KiUserCallbackDispatcher = 3
    SharedNtdll32ExpInterlockedPopEntrySListFault = 4
    SharedNtdll32ExpInterlockedPopEntrySListResume = 5
    SharedNtdll32ExpInterlockedPopEntrySListEnd = 6
    SharedNtdll32RtlUserThreadStart = 7
    SharedNtdll32pQueryProcessDebugInformationRemote = 8
    SharedNtdll32BaseAddress = 9
    SharedNtdll32LdrSystemDllInitBlock = 10
    Wow64SharedPageEntriesCount = 11

class DOMAIN_INFORMATION_CLASS(Enum):
    DomainPasswordInformation = 1  # q; s: DOMAIN_PASSWORD_INFORMATION
    DomainGeneralInformation = 2  # q: DOMAIN_GENERAL_INFORMATION
    DomainLogoffInformation = 3  # q; s: DOMAIN_LOGOFF_INFORMATION
    DomainOemInformation = 4  # q; s: DOMAIN_OEM_INFORMATION
    DomainNameInformation = 5  # q: DOMAIN_NAME_INFORMATION
    DomainReplicationInformation = 6  # q; s: DOMAIN_REPLICATION_INFORMATION
    DomainServerRoleInformation = 7  # q; s: DOMAIN_SERVER_ROLE_INFORMATION
    DomainModifiedInformation = 8  # q: DOMAIN_MODIFIED_INFORMATION
    DomainStateInformation = 9  # q; s: DOMAIN_STATE_INFORMATION
    DomainUasInformation = 10  # q; s: DOMAIN_UAS_INFORMATION
    DomainGeneralInformation2 = 11  # q: DOMAIN_GENERAL_INFORMATION2
    DomainLockoutInformation = 12  # q; s: DOMAIN_LOCKOUT_INFORMATION
    DomainModifiedInformation2 = 13  # q: DOMAIN_MODIFIED_INFORMATION2

class DOMAIN_SERVER_ENABLE_STATE(Enum):
    DomainServerEnabled = 1
    DomainServerDisabled = 2

class DOMAIN_SERVER_ROLE(Enum):
    DomainServerRoleBackup = 2
    DomainServerRolePrimary = 3

class DOMAIN_PASSWORD_CONSTRUCTION(Enum):
    DomainPasswordSimple = 1
    DomainPasswordComplex = 2

class DOMAIN_DISPLAY_INFORMATION(Enum):
    DomainDisplayUser = 1  # DOMAIN_DISPLAY_USER
    DomainDisplayMachine = 2  # DOMAIN_DISPLAY_MACHINE
    DomainDisplayGroup = 3  # DOMAIN_DISPLAY_GROUP
    DomainDisplayOemUser = 4  # DOMAIN_DISPLAY_OEM_USER
    DomainDisplayOemGroup = 5  # DOMAIN_DISPLAY_OEM_GROUP
    DomainDisplayServer = 6

class DOMAIN_LOCALIZABLE_ACCOUNTS_INFORMATION(Enum):
    DomainLocalizableAccountsBasic = 1

class GROUP_INFORMATION_CLASS(Enum):
    GroupGeneralInformation = 1  # q: GROUP_GENERAL_INFORMATION
    GroupNameInformation = 2  # q; s: GROUP_NAME_INFORMATION
    GroupAttributeInformation = 3  # q; s: GROUP_ATTRIBUTE_INFORMATION
    GroupAdminCommentInformation = 4  # q; s: GROUP_ADM_COMMENT_INFORMATION
    GroupReplicationInformation = 5

class ALIAS_INFORMATION_CLASS(Enum):
    AliasGeneralInformation = 1  # q: ALIAS_GENERAL_INFORMATION
    AliasNameInformation = 2  # q; s: ALIAS_NAME_INFORMATION
    AliasAdminCommentInformation = 3  # q; s: ALIAS_ADM_COMMENT_INFORMATION
    AliasReplicationInformation = 4
    AliasExtendedInformation = 5

class USER_INFORMATION_CLASS(Enum):
    UserGeneralInformation = 1  # q: USER_GENERAL_INFORMATION
    UserPreferencesInformation = 2  # q; s: USER_PREFERENCES_INFORMATION
    UserLogonInformation = 3  # q: USER_LOGON_INFORMATION
    UserLogonHoursInformation = 4  # q; s: USER_LOGON_HOURS_INFORMATION
    UserAccountInformation = 5  # q: USER_ACCOUNT_INFORMATION
    UserNameInformation = 6  # q; s: USER_NAME_INFORMATION
    UserAccountNameInformation = 7  # q; s: USER_ACCOUNT_NAME_INFORMATION
    UserFullNameInformation = 8  # q; s: USER_FULL_NAME_INFORMATION
    UserPrimaryGroupInformation = 9  # q; s: USER_PRIMARY_GROUP_INFORMATION
    UserHomeInformation = 10  # q; s: USER_HOME_INFORMATION // 10
    UserScriptInformation = 11  # q; s: USER_SCRIPT_INFORMATION
    UserProfileInformation = 12  # q; s: USER_PROFILE_INFORMATION
    UserAdminCommentInformation = 13  # q; s: USER_ADMIN_COMMENT_INFORMATION
    UserWorkStationsInformation = 14  # q; s: USER_WORKSTATIONS_INFORMATION
    UserSetPasswordInformation = 15  # s: USER_SET_PASSWORD_INFORMATION
    UserControlInformation = 16  # q; s: USER_CONTROL_INFORMATION
    UserExpiresInformation = 17  # q; s: USER_EXPIRES_INFORMATION
    UserInternal1Information = 18  # USER_INTERNAL1_INFORMATION
    UserInternal2Information = 19  # USER_INTERNAL2_INFORMATION
    UserParametersInformation = 20  # q; s: USER_PARAMETERS_INFORMATION // 20
    UserAllInformation = 21  # USER_ALL_INFORMATION
    UserInternal3Information = 22  # USER_INTERNAL3_INFORMATION
    UserInternal4Information = 23  # USER_INTERNAL4_INFORMATION
    UserInternal5Information = 24  # USER_INTERNAL5_INFORMATION
    UserInternal4InformationNew = 25  # USER_INTERNAL4_INFORMATION_NEW
    UserInternal5InformationNew = 26  # USER_INTERNAL5_INFORMATION_NEW
    UserInternal6Information = 27  # USER_INTERNAL6_INFORMATION
    UserExtendedInformation = 28  # USER_EXTENDED_INFORMATION
    UserLogonUIInformation = 29  # USER_LOGON_UI_INFORMATION
    UserUnknownTodoInformation = 30
    UserInternal7Information = 31  # USER_INTERNAL7_INFORMATION
    UserInternal8Information = 32  # USER_INTERNAL8_INFORMATION

class SECURITY_DB_DELTA_TYPE(Enum):
    SecurityDbNew = 1
    SecurityDbRename = 2
    SecurityDbDelete = 3
    SecurityDbChangeMemberAdd = 4
    SecurityDbChangeMemberSet = 5
    SecurityDbChangeMemberDel = 6
    SecurityDbChange = 7
    SecurityDbChangePassword = 8

class SECURITY_DB_OBJECT_TYPE(Enum):
    SecurityDbObjectSamDomain = 1
    SecurityDbObjectSamUser = 2
    SecurityDbObjectSamGroup = 3
    SecurityDbObjectSamAlias = 4
    SecurityDbObjectLsaPolicy = 5
    SecurityDbObjectLsaTDomain = 6
    SecurityDbObjectLsaAccount = 7
    SecurityDbObjectLsaSecret = 8

class SAM_ACCOUNT_TYPE(Enum):
    SamObjectUser = 1
    SamObjectGroup = 2
    SamObjectAlias = 3

class PASSWORD_POLICY_VALIDATION_TYPE(Enum):
    SamValidateAuthentication = 1
    SamValidatePasswordChange = 2
    SamValidatePasswordReset = 3

class SAM_VALIDATE_VALIDATION_STATUS(Enum):
    SamValidateSuccess = 0
    SamValidatePasswordMustChange = 1
    SamValidateAccountLockedOut = 2
    SamValidatePasswordExpired = 3
    SamValidatePasswordIncorrect = 4
    SamValidatePasswordIsInHistory = 5
    SamValidatePasswordTooShort = 6
    SamValidatePasswordTooLong = 7
    SamValidatePasswordNotComplexEnough = 8
    SamValidatePasswordTooRecent = 9
    SamValidatePasswordFilterError = 10

class SAM_GENERIC_OPERATION_TYPE(Enum):
    SamObjectChangeNotificationOperation = 0

class VDMSERVICECLASS(Enum):
    VdmStartExecution = 0
    VdmQueueInterrupt = 1
    VdmDelayInterrupt = 2
    VdmInitialize = 3
    VdmFeatures = 4
    VdmSetInt21Handler = 5
    VdmQueryDir = 6
    VdmPrinterDirectIoOpen = 7
    VdmPrinterDirectIoClose = 8
    VdmPrinterInitialize = 9
    VdmSetLdtEntries = 10
    VdmSetProcessLdtInfo = 11
    VdmAdlibEmulation = 12
    VdmPMCliControl = 13
    VdmQueryVdmProcess = 14
    VdmPreInitialize = 15

class TRACE_CONTROL_INFORMATION_CLASS(Enum):
    TraceControlStartLogger = 1  # inout WMI_LOGGER_INFORMATION
    TraceControlStopLogger = 2  # inout WMI_LOGGER_INFORMATION
    TraceControlQueryLogger = 3  # inout WMI_LOGGER_INFORMATION
    TraceControlUpdateLogger = 4  # inout WMI_LOGGER_INFORMATION
    TraceControlFlushLogger = 5  # inout WMI_LOGGER_INFORMATION
    TraceControlIncrementLoggerFile = 6  # inout WMI_LOGGER_INFORMATION
    TraceControlUnknown = 7
    TraceControlRealtimeConnect = 11
    TraceControlActivityIdCreate = 12
    TraceControlWdiDispatchControl = 13
    TraceControlRealtimeDisconnectConsumerByHandle = 14  # in HANDLE
    TraceControlRegisterGuidsCode = 15
    TraceControlReceiveNotification = 16
    TraceControlSendDataBlock = 17  # ETW_ENABLE_NOTIFICATION_PACKET
    TraceControlSendReplyDataBlock = 18
    TraceControlReceiveReplyDataBlock = 19
    TraceControlWdiUpdateSem = 20
    TraceControlEnumTraceGuidList = 21  # out GUID[]
    TraceControlGetTraceGuidInfo = 22  # in GUID, out TRACE_GUID_INFO
    TraceControlEnumerateTraceGuids = 23
    TraceControlRegisterSecurityProv = 24
    TraceControlQueryReferenceTime = 25
    TraceControlTrackProviderBinary = 26  # in HANDLE
    TraceControlAddNotificationEvent = 27
    TraceControlUpdateDisallowList = 28
    TraceControlSetEnableAllKeywordsCode = 29
    TraceControlSetProviderTraitsCode = 30
    TraceControlUseDescriptorTypeCode = 31
    TraceControlEnumTraceGroupList = 32
    TraceControlGetTraceGroupInfo = 33
    TraceControlTraceSetDisallowList = 34
    TraceControlSetCompressionSettings = 35
    TraceControlGetCompressionSettings = 36
    TraceControlUpdatePeriodicCaptureState = 37
    TraceControlGetPrivateSessionTraceHandle = 38
    TraceControlRegisterPrivateSession = 39
    TraceControlQuerySessionDemuxObject = 40
    TraceControlSetProviderBinaryTracking = 41
    TraceControlMaxLoggers = 42  # out ULONG
    TraceControlMaxPmcCounter = 43  # out ULONG
    TraceControlQueryUsedProcessorCount = 44  # ULONG // since WIN11
    TraceControlGetPmcOwnership = 45

class AUDIT_EVENT_TYPE(Enum):
    AuditEventObjectAccess = 0
    AuditEventDirectoryServiceAccess = 1

class TOKEN_TYPE(Enum):
    TokenPrimary = 1
    TokenImpersonation = 2

class KTMOBJECT_TYPE(Enum):
    KTMOBJECT_TRANSACTION = 0
    KTMOBJECT_TRANSACTION_MANAGER = 1
    KTMOBJECT_RESOURCE_MANAGER = 2
    KTMOBJECT_ENLISTMENT = 3
    KTMOBJECT_INVALID = 4

class DEVICE_POWER_STATE(Enum):
    PowerDeviceUnspecified = 0
    PowerDeviceD0 = 1
    PowerDeviceD1 = 2
    PowerDeviceD2 = 3
    PowerDeviceD3 = 4
    PowerDeviceMaximum = 5

class SYSTEM_POWER_STATE(Enum):
    PowerSystemUnspecified = 0
    PowerSystemWorking = 1
    PowerSystemSleeping1 = 2
    PowerSystemSleeping2 = 3
    PowerSystemSleeping3 = 4
    PowerSystemHibernate = 5
    PowerSystemShutdown = 6
    PowerSystemMaximum = 7

class ENLISTMENT_INFORMATION_CLASS(Enum):
    EnlistmentBasicInformation = 0
    EnlistmentRecoveryInformation = 1
    EnlistmentCrmInformation = 2

class JOBOBJECTINFOCLASS(Enum):
    JobObjectBasicAccountingInformation = 1
    JobObjectBasicLimitInformation = 2
    JobObjectBasicProcessIdList = 3
    JobObjectBasicUIRestrictions = 4
    JobObjectSecurityLimitInformation = 5  # deprecated
    JobObjectEndOfJobTimeInformation = 6
    JobObjectAssociateCompletionPortInformation = 7
    JobObjectBasicAndIoAccountingInformation = 8
    JobObjectExtendedLimitInformation = 9
    JobObjectJobSetInformation = 10
    JobObjectGroupInformation = 11
    JobObjectNotificationLimitInformation = 12
    JobObjectLimitViolationInformation = 13
    JobObjectGroupInformationEx = 14
    JobObjectCpuRateControlInformation = 15
    JobObjectCompletionFilter = 16
    JobObjectCompletionCounter = 17
    JobObjectReserved1Information = 18
    JobObjectReserved2Information = 19
    JobObjectReserved3Information = 20
    JobObjectReserved4Information = 21
    JobObjectReserved5Information = 22
    JobObjectReserved6Information = 23
    JobObjectReserved7Information = 24
    JobObjectReserved8Information = 25
    JobObjectReserved9Information = 26
    JobObjectReserved10Information = 27
    JobObjectReserved11Information = 28
    JobObjectReserved12Information = 29
    JobObjectReserved13Information = 30
    JobObjectReserved14Information = 31
    JobObjectNetRateControlInformation = 32
    JobObjectNotificationLimitInformation2 = 33
    JobObjectLimitViolationInformation2 = 34
    JobObjectCreateSilo = 35
    JobObjectSiloBasicInformation = 36
    JobObjectReserved15Information = 37
    JobObjectReserved16Information = 38
    JobObjectReserved17Information = 39
    JobObjectReserved18Information = 40
    JobObjectReserved19Information = 41
    JobObjectReserved20Information = 42
    JobObjectReserved21Information = 43
    JobObjectReserved22Information = 44
    JobObjectReserved23Information = 45
    JobObjectReserved24Information = 46
    JobObjectReserved25Information = 47
    JobObjectReserved26Information = 48
    JobObjectReserved27Information = 49
    MaxJobObjectInfoClass = 50

class RESOURCEMANAGER_INFORMATION_CLASS(Enum):
    ResourceManagerBasicInformation = 0
    ResourceManagerCompletionInformation = 1

class TOKEN_INFORMATION_CLASS(Enum):
    TokenUser = 1
    TokenGroups = 2
    TokenPrivileges = 3
    TokenOwner = 4
    TokenPrimaryGroup = 5
    TokenDefaultDacl = 6
    TokenSource = 7
    TokenType = 8
    TokenImpersonationLevel = 9
    TokenStatistics = 10
    TokenRestrictedSids = 11
    TokenSessionId = 12
    TokenGroupsAndPrivileges = 13
    TokenSessionReference = 14
    TokenSandBoxInert = 15
    TokenAuditPolicy = 16
    TokenOrigin = 17
    TokenElevationType = 18
    TokenLinkedToken = 19
    TokenElevation = 20
    TokenHasRestrictions = 21
    TokenAccessInformation = 22
    TokenVirtualizationAllowed = 23
    TokenVirtualizationEnabled = 24
    TokenIntegrityLevel = 25
    TokenUIAccess = 26
    TokenMandatoryPolicy = 27
    TokenLogonSid = 28
    TokenIsAppContainer = 29
    TokenCapabilities = 30
    TokenAppContainerSid = 31
    TokenAppContainerNumber = 32
    TokenUserClaimAttributes = 33
    TokenDeviceClaimAttributes = 34
    TokenRestrictedUserClaimAttributes = 35
    TokenRestrictedDeviceClaimAttributes = 36
    TokenDeviceGroups = 37
    TokenRestrictedDeviceGroups = 38
    TokenSecurityAttributes = 39
    TokenIsRestricted = 40
    TokenProcessTrustLevel = 41
    TokenPrivateNameSpace = 42
    TokenSingletonAttributes = 43
    TokenBnoIsolation = 44
    TokenChildProcessFlags = 45
    TokenIsLessPrivilegedAppContainer = 46
    TokenIsSandboxed = 47
    TokenIsAppSilo = 48
    MaxTokenInfoClass = 49  # MaxTokenInfoClass should always be the last enum

class TRANSACTION_INFORMATION_CLASS(Enum):
    TransactionBasicInformation = 0
    TransactionPropertiesInformation = 1
    TransactionEnlistmentInformation = 2
    TransactionSuperiorEnlistmentInformation = 3
    TransactionBindInformation = 4  # private and deprecated
    TransactionDTCPrivateInformation = 5  # private and deprecated

class TRANSACTIONMANAGER_INFORMATION_CLASS(Enum):
    TransactionManagerBasicInformation = 0
    TransactionManagerLogInformation = 1
    TransactionManagerLogPathInformation = 2
    TransactionManagerRecoveryInformation = 4
    TransactionManagerOnlineProbeInformation = 3
    TransactionManagerOldestTransactionInformation = 5

