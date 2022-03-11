# Automatically generated with parse_phnt.py, do not edit
from enum import Enum
from .ntprimitives import make_global

class EVENT_TYPE(Enum):
    NotificationEvent = 0
    SynchronizationEvent = 1
make_global(EVENT_TYPE)

class TIMER_TYPE(Enum):
    NotificationTimer = 0
    SynchronizationTimer = 1
make_global(TIMER_TYPE)

class WAIT_TYPE(Enum):
    WaitAll = 0
    WaitAny = 1
    WaitNotification = 2
make_global(WAIT_TYPE)

class NT_PRODUCT_TYPE(Enum):
    NtProductWinNt = 1
    NtProductLanManNt = 2
    NtProductServer = 3
make_global(NT_PRODUCT_TYPE)

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
make_global(SUITE_TYPE)

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
make_global(KTHREAD_STATE)

class KHETERO_CPU_POLICY(Enum):
    KHeteroCpuPolicyAll = 0
    KHeteroCpuPolicyLarge = 1
    KHeteroCpuPolicyLargeOrIdle = 2
    KHeteroCpuPolicySmall = 3
    KHeteroCpuPolicySmallOrIdle = 4
    KHeteroCpuPolicyDynamic = 5
    KHeteroCpuPolicyStaticMax = 6
    KHeteroCpuPolicyBiasedSmall = 7
    KHeteroCpuPolicyBiasedLarge = 8
    KHeteroCpuPolicyDefault = 9
    KHeteroCpuPolicyMax = 10
make_global(KHETERO_CPU_POLICY)

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
    MaximumWaitReason = 40
make_global(KWAIT_REASON)

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
make_global(KPROFILE_SOURCE)

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
make_global(LDR_DDAG_STATE)

class LDR_DLL_LOAD_REASON(Enum):
    LoadReasonStaticDependency = 0
    LoadReasonStaticForwarderDependency = 1
    LoadReasonDynamicForwarderDependency = 2
    LoadReasonDelayloadDependency = 3
    LoadReasonDynamicLoad = 4
    LoadReasonAsImageLoad = 5
    LoadReasonAsDataLoad = 6
    LoadReasonEnclavePrimary = 7
    LoadReasonEnclaveDependency = 8
    LoadReasonUnknown = -1
make_global(LDR_DLL_LOAD_REASON)

class FILTER_BOOT_OPTION_OPERATION(Enum):
    FilterBootOptionOperationOpenSystemStore = 0
    FilterBootOptionOperationSetElement = 1
    FilterBootOptionOperationDeleteElement = 2
    FilterBootOptionOperationMax = 3
make_global(FILTER_BOOT_OPTION_OPERATION)

class EVENT_INFORMATION_CLASS(Enum):
    EventBasicInformation = 0
make_global(EVENT_INFORMATION_CLASS)

class MUTANT_INFORMATION_CLASS(Enum):
    MutantBasicInformation = 0
    MutantOwnerInformation = 1
make_global(MUTANT_INFORMATION_CLASS)

class SEMAPHORE_INFORMATION_CLASS(Enum):
    SemaphoreBasicInformation = 0
make_global(SEMAPHORE_INFORMATION_CLASS)

class TIMER_INFORMATION_CLASS(Enum):
    TimerBasicInformation = 0
make_global(TIMER_INFORMATION_CLASS)

class TIMER_SET_INFORMATION_CLASS(Enum):
    TimerSetCoalescableTimer = 0
    MaxTimerInfoClass = 1
make_global(TIMER_SET_INFORMATION_CLASS)

class WNF_STATE_NAME_LIFETIME(Enum):
    WnfWellKnownStateName = 0
    WnfPermanentStateName = 1
    WnfPersistentStateName = 2
    WnfTemporaryStateName = 3
make_global(WNF_STATE_NAME_LIFETIME)

class WNF_STATE_NAME_INFORMATION(Enum):
    WnfInfoStateNameExist = 0
    WnfInfoSubscribersPresent = 1
    WnfInfoIsQuiescent = 2
make_global(WNF_STATE_NAME_INFORMATION)

class WNF_DATA_SCOPE(Enum):
    WnfDataScopeSystem = 0
    WnfDataScopeSession = 1
    WnfDataScopeUser = 2
    WnfDataScopeProcess = 3
    WnfDataScopeMachine = 4
make_global(WNF_DATA_SCOPE)

class WORKERFACTORYINFOCLASS(Enum):
    WorkerFactoryTimeout = 0
    WorkerFactoryRetryTimeout = 1
    WorkerFactoryIdleTimeout = 2
    WorkerFactoryBindingCount = 3
    WorkerFactoryThreadMinimum = 4
    WorkerFactoryThreadMaximum = 5
    WorkerFactoryPaused = 6
    WorkerFactoryBasicInformation = 7
    WorkerFactoryAdjustThreadGoal = 8
    WorkerFactoryCallbackType = 9
    WorkerFactoryStackInformation = 10
    WorkerFactoryThreadBasePriority = 11
    WorkerFactoryTimeoutWaiters = 12
    WorkerFactoryFlags = 13
    WorkerFactoryThreadSoftMaximum = 14
    WorkerFactoryThreadCpuSets = 15
    MaxWorkerFactoryInfoClass = 16
make_global(WORKERFACTORYINFOCLASS)

class SYSTEM_INFORMATION_CLASS(Enum):
    SystemBasicInformation = 0
    SystemProcessorInformation = 1
    SystemPerformanceInformation = 2
    SystemTimeOfDayInformation = 3
    SystemPathInformation = 4
    SystemProcessInformation = 5
    SystemCallCountInformation = 6
    SystemDeviceInformation = 7
    SystemProcessorPerformanceInformation = 8
    SystemFlagsInformation = 9
    SystemCallTimeInformation = 10
    SystemModuleInformation = 11
    SystemLocksInformation = 12
    SystemStackTraceInformation = 13
    SystemPagedPoolInformation = 14
    SystemNonPagedPoolInformation = 15
    SystemHandleInformation = 16
    SystemObjectInformation = 17
    SystemPageFileInformation = 18
    SystemVdmInstemulInformation = 19
    SystemVdmBopInformation = 20
    SystemFileCacheInformation = 21
    SystemPoolTagInformation = 22
    SystemInterruptInformation = 23
    SystemDpcBehaviorInformation = 24
    SystemFullMemoryInformation = 25
    SystemLoadGdiDriverInformation = 26
    SystemUnloadGdiDriverInformation = 27
    SystemTimeAdjustmentInformation = 28
    SystemSummaryMemoryInformation = 29
    SystemMirrorMemoryInformation = 30
    SystemPerformanceTraceInformation = 31
    SystemObsolete0 = 32
    SystemExceptionInformation = 33
    SystemCrashDumpStateInformation = 34
    SystemKernelDebuggerInformation = 35
    SystemContextSwitchInformation = 36
    SystemRegistryQuotaInformation = 37
    SystemExtendServiceTableInformation = 38
    SystemPrioritySeperation = 39
    SystemVerifierAddDriverInformation = 40
    SystemVerifierRemoveDriverInformation = 41
    SystemProcessorIdleInformation = 42
    SystemLegacyDriverInformation = 43
    SystemCurrentTimeZoneInformation = 44
    SystemLookasideInformation = 45
    SystemTimeSlipNotification = 46
    SystemSessionCreate = 47
    SystemSessionDetach = 48
    SystemSessionInformation = 49
    SystemRangeStartInformation = 50
    SystemVerifierInformation = 51
    SystemVerifierThunkExtend = 52
    SystemSessionProcessInformation = 53
    SystemLoadGdiDriverInSystemSpace = 54
    SystemNumaProcessorMap = 55
    SystemPrefetcherInformation = 56
    SystemExtendedProcessInformation = 57
    SystemRecommendedSharedDataAlignment = 58
    SystemComPlusPackage = 59
    SystemNumaAvailableMemory = 60
    SystemProcessorPowerInformation = 61
    SystemEmulationBasicInformation = 62
    SystemEmulationProcessorInformation = 63
    SystemExtendedHandleInformation = 64
    SystemLostDelayedWriteInformation = 65
    SystemBigPoolInformation = 66
    SystemSessionPoolTagInformation = 67
    SystemSessionMappedViewInformation = 68
    SystemHotpatchInformation = 69
    SystemObjectSecurityMode = 70
    SystemWatchdogTimerHandler = 71
    SystemWatchdogTimerInformation = 72
    SystemLogicalProcessorInformation = 73
    SystemWow64SharedInformationObsolete = 74
    SystemRegisterFirmwareTableInformationHandler = 75
    SystemFirmwareTableInformation = 76
    SystemModuleInformationEx = 77
    SystemVerifierTriageInformation = 78
    SystemSuperfetchInformation = 79
    SystemMemoryListInformation = 80
    SystemFileCacheInformationEx = 81
    SystemThreadPriorityClientIdInformation = 82
    SystemProcessorIdleCycleTimeInformation = 83
    SystemVerifierCancellationInformation = 84
    SystemProcessorPowerInformationEx = 85
    SystemRefTraceInformation = 86
    SystemSpecialPoolInformation = 87
    SystemProcessIdInformation = 88
    SystemErrorPortInformation = 89
    SystemBootEnvironmentInformation = 90
    SystemHypervisorInformation = 91
    SystemVerifierInformationEx = 92
    SystemTimeZoneInformation = 93
    SystemImageFileExecutionOptionsInformation = 94
    SystemCoverageInformation = 95
    SystemPrefetchPatchInformation = 96
    SystemVerifierFaultsInformation = 97
    SystemSystemPartitionInformation = 98
    SystemSystemDiskInformation = 99
    SystemProcessorPerformanceDistribution = 100
    SystemNumaProximityNodeInformation = 101
    SystemDynamicTimeZoneInformation = 102
    SystemCodeIntegrityInformation = 103
    SystemProcessorMicrocodeUpdateInformation = 104
    SystemProcessorBrandString = 105
    SystemVirtualAddressInformation = 106
    SystemLogicalProcessorAndGroupInformation = 107
    SystemProcessorCycleTimeInformation = 108
    SystemStoreInformation = 109
    SystemRegistryAppendString = 110
    SystemAitSamplingValue = 111
    SystemVhdBootInformation = 112
    SystemCpuQuotaInformation = 113
    SystemNativeBasicInformation = 114
    SystemErrorPortTimeouts = 115
    SystemLowPriorityIoInformation = 116
    SystemTpmBootEntropyInformation = 117
    SystemVerifierCountersInformation = 118
    SystemPagedPoolInformationEx = 119
    SystemSystemPtesInformationEx = 120
    SystemNodeDistanceInformation = 121
    SystemAcpiAuditInformation = 122
    SystemBasicPerformanceInformation = 123
    SystemQueryPerformanceCounterInformation = 124
    SystemSessionBigPoolInformation = 125
    SystemBootGraphicsInformation = 126
    SystemScrubPhysicalMemoryInformation = 127
    SystemBadPageInformation = 128
    SystemProcessorProfileControlArea = 129
    SystemCombinePhysicalMemoryInformation = 130
    SystemEntropyInterruptTimingInformation = 131
    SystemConsoleInformation = 132
    SystemPlatformBinaryInformation = 133
    SystemPolicyInformation = 134
    SystemHypervisorProcessorCountInformation = 135
    SystemDeviceDataInformation = 136
    SystemDeviceDataEnumerationInformation = 137
    SystemMemoryTopologyInformation = 138
    SystemMemoryChannelInformation = 139
    SystemBootLogoInformation = 140
    SystemProcessorPerformanceInformationEx = 141
    SystemCriticalProcessErrorLogInformation = 142
    SystemSecureBootPolicyInformation = 143
    SystemPageFileInformationEx = 144
    SystemSecureBootInformation = 145
    SystemEntropyInterruptTimingRawInformation = 146
    SystemPortableWorkspaceEfiLauncherInformation = 147
    SystemFullProcessInformation = 148
    SystemKernelDebuggerInformationEx = 149
    SystemBootMetadataInformation = 150
    SystemSoftRebootInformation = 151
    SystemElamCertificateInformation = 152
    SystemOfflineDumpConfigInformation = 153
    SystemProcessorFeaturesInformation = 154
    SystemRegistryReconciliationInformation = 155
    SystemEdidInformation = 156
    SystemManufacturingInformation = 157
    SystemEnergyEstimationConfigInformation = 158
    SystemHypervisorDetailInformation = 159
    SystemProcessorCycleStatsInformation = 160
    SystemVmGenerationCountInformation = 161
    SystemTrustedPlatformModuleInformation = 162
    SystemKernelDebuggerFlags = 163
    SystemCodeIntegrityPolicyInformation = 164
    SystemIsolatedUserModeInformation = 165
    SystemHardwareSecurityTestInterfaceResultsInformation = 166
    SystemSingleModuleInformation = 167
    SystemAllowedCpuSetsInformation = 168
    SystemVsmProtectionInformation = 169
    SystemInterruptCpuSetsInformation = 170
    SystemSecureBootPolicyFullInformation = 171
    SystemCodeIntegrityPolicyFullInformation = 172
    SystemAffinitizedInterruptProcessorInformation = 173
    SystemRootSiloInformation = 174
    SystemCpuSetInformation = 175
    SystemCpuSetTagInformation = 176
    SystemWin32WerStartCallout = 177
    SystemSecureKernelProfileInformation = 178
    SystemCodeIntegrityPlatformManifestInformation = 179
    SystemInterruptSteeringInformation = 180
    SystemSupportedProcessorArchitectures = 181
    SystemMemoryUsageInformation = 182
    SystemCodeIntegrityCertificateInformation = 183
    SystemPhysicalMemoryInformation = 184
    SystemControlFlowTransition = 185
    SystemKernelDebuggingAllowed = 186
    SystemActivityModerationExeState = 187
    SystemActivityModerationUserSettings = 188
    SystemCodeIntegrityPoliciesFullInformation = 189
    SystemCodeIntegrityUnlockInformation = 190
    SystemIntegrityQuotaInformation = 191
    SystemFlushInformation = 192
    SystemProcessorIdleMaskInformation = 193
    SystemSecureDumpEncryptionInformation = 194
    SystemWriteConstraintInformation = 195
    SystemKernelVaShadowInformation = 196
    SystemHypervisorSharedPageInformation = 197
    SystemFirmwareBootPerformanceInformation = 198
    SystemCodeIntegrityVerificationInformation = 199
    SystemFirmwarePartitionInformation = 200
    SystemSpeculationControlInformation = 201
    SystemDmaGuardPolicyInformation = 202
    SystemEnclaveLaunchControlInformation = 203
    SystemWorkloadAllowedCpuSetsInformation = 204
    SystemCodeIntegrityUnlockModeInformation = 205
    SystemLeapSecondInformation = 206
    SystemFlags2Information = 207
    SystemSecurityModelInformation = 208
    SystemCodeIntegritySyntheticCacheInformation = 209
    SystemFeatureConfigurationInformation = 210
    SystemFeatureConfigurationSectionInformation = 211
    SystemFeatureUsageSubscriptionInformation = 212
    SystemSecureSpeculationControlInformation = 213
    SystemSpacesBootInformation = 214
    SystemFwRamdiskInformation = 215
    SystemWheaIpmiHardwareInformation = 216
    SystemDifSetRuleClassInformation = 217
    SystemDifClearRuleClassInformation = 218
    SystemDifApplyPluginVerificationOnDriver = 219
    SystemDifRemovePluginVerificationOnDriver = 220
    SystemShadowStackInformation = 221
    SystemBuildVersionInformation = 222
    SystemPoolLimitInformation = 223
    SystemCodeIntegrityAddDynamicStore = 224
    SystemCodeIntegrityClearDynamicStores = 225
    SystemDifPoolTrackingInformation = 226
    SystemPoolZeroingInformation = 227
    MaxSystemInfoClass = 228
make_global(SYSTEM_INFORMATION_CLASS)

class EVENT_TRACE_INFORMATION_CLASS(Enum):
    EventTraceKernelVersionInformation = 0
    EventTraceGroupMaskInformation = 1
    EventTracePerformanceInformation = 2
    EventTraceTimeProfileInformation = 3
    EventTraceSessionSecurityInformation = 4
    EventTraceSpinlockInformation = 5
    EventTraceStackTracingInformation = 6
    EventTraceExecutiveResourceInformation = 7
    EventTraceHeapTracingInformation = 8
    EventTraceHeapSummaryTracingInformation = 9
    EventTracePoolTagFilterInformation = 10
    EventTracePebsTracingInformation = 11
    EventTraceProfileConfigInformation = 12
    EventTraceProfileSourceListInformation = 13
    EventTraceProfileEventListInformation = 14
    EventTraceProfileCounterListInformation = 15
    EventTraceStackCachingInformation = 16
    EventTraceObjectTypeFilterInformation = 17
    EventTraceSoftRestartInformation = 18
    EventTraceLastBranchConfigurationInformation = 19
    EventTraceLastBranchEventListInformation = 20
    EventTraceProfileSourceAddInformation = 21
    EventTraceProfileSourceRemoveInformation = 22
    EventTraceProcessorTraceConfigurationInformation = 23
    EventTraceProcessorTraceEventListInformation = 24
    EventTraceCoverageSamplerInformation = 25
    EventTraceUnifiedStackCachingInformation = 26
    MaxEventTraceInfoClass = 27
make_global(EVENT_TRACE_INFORMATION_CLASS)

class SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS(Enum):
    SystemCrashDumpDisable = 0
    SystemCrashDumpReconfigure = 1
    SystemCrashDumpInitializationComplete = 2
make_global(SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS)

class SYSTEM_FIRMWARE_TABLE_ACTION(Enum):
    SystemFirmwareTableEnumerate = 0
    SystemFirmwareTableGet = 1
    SystemFirmwareTableMax = 2
make_global(SYSTEM_FIRMWARE_TABLE_ACTION)

class SYSTEM_MEMORY_LIST_COMMAND(Enum):
    MemoryCaptureAccessedBits = 0
    MemoryCaptureAndResetAccessedBits = 1
    MemoryEmptyWorkingSets = 2
    MemoryFlushModifiedList = 3
    MemoryPurgeStandbyList = 4
    MemoryPurgeLowPriorityStandbyList = 5
    MemoryCommandMax = 6
make_global(SYSTEM_MEMORY_LIST_COMMAND)

class SYSTEM_VA_TYPE(Enum):
    SystemVaTypeAll = 0
    SystemVaTypeNonPagedPool = 1
    SystemVaTypePagedPool = 2
    SystemVaTypeSystemCache = 3
    SystemVaTypeSystemPtes = 4
    SystemVaTypeSessionSpace = 5
    SystemVaTypeMax = 6
make_global(SYSTEM_VA_TYPE)

class SYSTEM_STORE_INFORMATION_CLASS(Enum):
    SystemStoreCompressionInformation = 22
make_global(SYSTEM_STORE_INFORMATION_CLASS)

class TPM_BOOT_ENTROPY_RESULT_CODE(Enum):
    TpmBootEntropyStructureUninitialized = 0
    TpmBootEntropyDisabledByPolicy = 1
    TpmBootEntropyNoTpmFound = 2
    TpmBootEntropyTpmError = 3
    TpmBootEntropySuccess = 4
make_global(TPM_BOOT_ENTROPY_RESULT_CODE)

class SYSTEM_PIXEL_FORMAT(Enum):
    SystemPixelFormatUnknown = 0
    SystemPixelFormatR8G8B8 = 1
    SystemPixelFormatR8G8B8X8 = 2
    SystemPixelFormatB8G8R8 = 3
    SystemPixelFormatB8G8R8X8 = 4
make_global(SYSTEM_PIXEL_FORMAT)

class SYSTEM_PROCESS_CLASSIFICATION(Enum):
    SystemProcessClassificationNormal = 0
    SystemProcessClassificationSystem = 1
    SystemProcessClassificationSecureSystem = 2
    SystemProcessClassificationMemCompression = 3
    SystemProcessClassificationRegistry = 4
    SystemProcessClassificationMaximum = 5
make_global(SYSTEM_PROCESS_CLASSIFICATION)

class SYSTEM_ACTIVITY_MODERATION_STATE(Enum):
    SystemActivityModerationStateSystemManaged = 0
    SystemActivityModerationStateUserManagedAllowThrottling = 1
    SystemActivityModerationStateUserManagedDisableThrottling = 2
    MaxSystemActivityModerationState = 3
make_global(SYSTEM_ACTIVITY_MODERATION_STATE)

class SYSTEM_ACTIVITY_MODERATION_APP_TYPE(Enum):
    SystemActivityModerationAppTypeClassic = 0
    SystemActivityModerationAppTypePackaged = 1
    MaxSystemActivityModerationAppType = 2
make_global(SYSTEM_ACTIVITY_MODERATION_APP_TYPE)

class SYSDBG_COMMAND(Enum):
    SysDbgQueryModuleInformation = 0
    SysDbgQueryTraceInformation = 1
    SysDbgSetTracepoint = 2
    SysDbgSetSpecialCall = 3
    SysDbgClearSpecialCalls = 4
    SysDbgQuerySpecialCalls = 5
    SysDbgBreakPoint = 6
    SysDbgQueryVersion = 7
    SysDbgReadVirtual = 8
    SysDbgWriteVirtual = 9
    SysDbgReadPhysical = 10
    SysDbgWritePhysical = 11
    SysDbgReadControlSpace = 12
    SysDbgWriteControlSpace = 13
    SysDbgReadIoSpace = 14
    SysDbgWriteIoSpace = 15
    SysDbgReadMsr = 16
    SysDbgWriteMsr = 17
    SysDbgReadBusData = 18
    SysDbgWriteBusData = 19
    SysDbgCheckLowMemory = 20
    SysDbgEnableKernelDebugger = 21
    SysDbgDisableKernelDebugger = 22
    SysDbgGetAutoKdEnable = 23
    SysDbgSetAutoKdEnable = 24
    SysDbgGetPrintBufferSize = 25
    SysDbgSetPrintBufferSize = 26
    SysDbgGetKdUmExceptionEnable = 27
    SysDbgSetKdUmExceptionEnable = 28
    SysDbgGetTriageDump = 29
    SysDbgGetKdBlockEnable = 30
    SysDbgSetKdBlockEnable = 31
    SysDbgRegisterForUmBreakInfo = 32
    SysDbgGetUmBreakPid = 33
    SysDbgClearUmBreakPid = 34
    SysDbgGetUmAttachPid = 35
    SysDbgClearUmAttachPid = 36
    SysDbgGetLiveKernelDump = 37
make_global(SYSDBG_COMMAND)

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
make_global(HARDERROR_RESPONSE_OPTION)

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
make_global(HARDERROR_RESPONSE)

class ALTERNATIVE_ARCHITECTURE_TYPE(Enum):
    StandardDesign = 0
    NEC98x86 = 1
    EndAlternatives = 2
make_global(ALTERNATIVE_ARCHITECTURE_TYPE)

class ATOM_INFORMATION_CLASS(Enum):
    AtomBasicInformation = 0
    AtomTableInformation = 1
make_global(ATOM_INFORMATION_CLASS)

class SHUTDOWN_ACTION(Enum):
    ShutdownNoReboot = 0
    ShutdownReboot = 1
    ShutdownPowerOff = 2
make_global(SHUTDOWN_ACTION)

class MEMORY_INFORMATION_CLASS(Enum):
    MemoryBasicInformation = 0
    MemoryWorkingSetInformation = 1
    MemoryMappedFilenameInformation = 2
    MemoryRegionInformation = 3
    MemoryWorkingSetExInformation = 4
    MemorySharedCommitInformation = 5
    MemoryImageInformation = 6
    MemoryRegionInformationEx = 7
    MemoryPrivilegedBasicInformation = 8
    MemoryEnclaveImageInformation = 9
    MemoryBasicInformationCapped = 10
    MemoryPhysicalContiguityInformation = 11
    MaxMemoryInfoClass = 12
make_global(MEMORY_INFORMATION_CLASS)

class MEMORY_WORKING_SET_EX_LOCATION(Enum):
    MemoryLocationInvalid = 0
    MemoryLocationResident = 1
    MemoryLocationPagefile = 2
    MemoryLocationReserved = 3
make_global(MEMORY_WORKING_SET_EX_LOCATION)

class MEMORY_PHYSICAL_CONTIGUITY_UNIT_STATE(Enum):
    MemoryNotContiguous = 0
    MemoryAlignedAndContiguous = 1
    MemoryNotResident = 2
    MemoryNotEligibleToMakeContiguous = 3
    MemoryContiguityStateMax = 4
make_global(MEMORY_PHYSICAL_CONTIGUITY_UNIT_STATE)

class SECTION_INFORMATION_CLASS(Enum):
    SectionBasicInformation = 0
    SectionImageInformation = 1
    SectionRelocationInformation = 2
    SectionOriginalBaseInformation = 3
    SectionInternalImageInformation = 4
    MaxSectionInfoClass = 5
make_global(SECTION_INFORMATION_CLASS)

class SECTION_INHERIT(Enum):
    ViewShare = 1
    ViewUnmap = 2
make_global(SECTION_INHERIT)

class VIRTUAL_MEMORY_INFORMATION_CLASS(Enum):
    VmPrefetchInformation = 0
    VmPagePriorityInformation = 1
    VmCfgCallTargetInformation = 2
    VmPageDirtyStateInformation = 3
    VmImageHotPatchInformation = 4
    VmPhysicalContiguityInformation = 5
    VmVirtualMachinePrepopulateInformation = 6
    MaxVmInfoClass = 7
make_global(VIRTUAL_MEMORY_INFORMATION_CLASS)

class MEMORY_PARTITION_INFORMATION_CLASS(Enum):
    SystemMemoryPartitionInformation = 0
    SystemMemoryPartitionMoveMemory = 1
    SystemMemoryPartitionAddPagefile = 2
    SystemMemoryPartitionCombineMemory = 3
    SystemMemoryPartitionInitialAddMemory = 4
    SystemMemoryPartitionGetMemoryEvents = 5
    SystemMemoryPartitionMax = 6
make_global(MEMORY_PARTITION_INFORMATION_CLASS)

class OBJECT_INFORMATION_CLASS(Enum):
    ObjectBasicInformation = 0
    ObjectNameInformation = 1
    ObjectTypeInformation = 2
    ObjectTypesInformation = 3
    ObjectHandleFlagInformation = 4
    ObjectSessionInformation = 5
    ObjectSessionObjectInformation = 6
    MaxObjectInfoClass = 7
make_global(OBJECT_INFORMATION_CLASS)

class SYMBOLIC_LINK_INFO_CLASS(Enum):
    SymbolicLinkGlobalInformation = 1
    SymbolicLinkAccessMask = 2
    MaxnSymbolicLinkInfoClass = 3
make_global(SYMBOLIC_LINK_INFO_CLASS)

class PROCESSINFOCLASS(Enum):
    ProcessBasicInformation = 0
    ProcessQuotaLimits = 1
    ProcessIoCounters = 2
    ProcessVmCounters = 3
    ProcessTimes = 4
    ProcessBasePriority = 5
    ProcessRaisePriority = 6
    ProcessDebugPort = 7
    ProcessExceptionPort = 8
    ProcessAccessToken = 9
    ProcessLdtInformation = 10
    ProcessLdtSize = 11
    ProcessDefaultHardErrorMode = 12
    ProcessIoPortHandlers = 13
    ProcessPooledUsageAndLimits = 14
    ProcessWorkingSetWatch = 15
    ProcessUserModeIOPL = 16
    ProcessEnableAlignmentFaultFixup = 17
    ProcessPriorityClass = 18
    ProcessWx86Information = 19
    ProcessHandleCount = 20
    ProcessAffinityMask = 21
    ProcessPriorityBoost = 22
    ProcessDeviceMap = 23
    ProcessSessionInformation = 24
    ProcessForegroundInformation = 25
    ProcessWow64Information = 26
    ProcessImageFileName = 27
    ProcessLUIDDeviceMapsEnabled = 28
    ProcessBreakOnTermination = 29
    ProcessDebugObjectHandle = 30
    ProcessDebugFlags = 31
    ProcessHandleTracing = 32
    ProcessIoPriority = 33
    ProcessExecuteFlags = 34
    ProcessTlsInformation = 35
    ProcessCookie = 36
    ProcessImageInformation = 37
    ProcessCycleTime = 38
    ProcessPagePriority = 39
    ProcessInstrumentationCallback = 40
    ProcessThreadStackAllocation = 41
    ProcessWorkingSetWatchEx = 42
    ProcessImageFileNameWin32 = 43
    ProcessImageFileMapping = 44
    ProcessAffinityUpdateMode = 45
    ProcessMemoryAllocationMode = 46
    ProcessGroupInformation = 47
    ProcessTokenVirtualizationEnabled = 48
    ProcessConsoleHostProcess = 49
    ProcessWindowInformation = 50
    ProcessHandleInformation = 51
    ProcessMitigationPolicy = 52
    ProcessDynamicFunctionTableInformation = 53
    ProcessHandleCheckingMode = 54
    ProcessKeepAliveCount = 55
    ProcessRevokeFileHandles = 56
    ProcessWorkingSetControl = 57
    ProcessHandleTable = 58
    ProcessCheckStackExtentsMode = 59
    ProcessCommandLineInformation = 60
    ProcessProtectionInformation = 61
    ProcessMemoryExhaustion = 62
    ProcessFaultInformation = 63
    ProcessTelemetryIdInformation = 64
    ProcessCommitReleaseInformation = 65
    ProcessDefaultCpuSetsInformation = 66
    ProcessAllowedCpuSetsInformation = 67
    ProcessSubsystemProcess = 68
    ProcessJobMemoryInformation = 69
    ProcessInPrivate = 70
    ProcessRaiseUMExceptionOnInvalidHandleClose = 71
    ProcessIumChallengeResponse = 72
    ProcessChildProcessInformation = 73
    ProcessHighGraphicsPriorityInformation = 74
    ProcessSubsystemInformation = 75
    ProcessEnergyValues = 76
    ProcessPowerThrottlingState = 77
    ProcessReserved3Information = 78
    ProcessWin32kSyscallFilterInformation = 79
    ProcessDisableSystemAllowedCpuSets = 80
    ProcessWakeInformation = 81
    ProcessEnergyTrackingState = 82
    ProcessManageWritesToExecutableMemory = 83
    ProcessCaptureTrustletLiveDump = 84
    ProcessTelemetryCoverage = 85
    ProcessEnclaveInformation = 86
    ProcessEnableReadWriteVmLogging = 87
    ProcessUptimeInformation = 88
    ProcessImageSection = 89
    ProcessDebugAuthInformation = 90
    ProcessSystemResourceManagement = 91
    ProcessSequenceNumber = 92
    ProcessLoaderDetour = 93
    ProcessSecurityDomainInformation = 94
    ProcessCombineSecurityDomainsInformation = 95
    ProcessEnableLogging = 96
    ProcessLeapSecondInformation = 97
    ProcessFiberShadowStackAllocation = 98
    ProcessFreeFiberShadowStackAllocation = 99
    ProcessAltSystemCallInformation = 100
    ProcessDynamicEHContinuationTargets = 101
    ProcessDynamicEnforcedCetCompatibleRanges = 102
    MaxProcessInfoClass = 103
make_global(PROCESSINFOCLASS)

class THREADINFOCLASS(Enum):
    ThreadBasicInformation = 0
    ThreadTimes = 1
    ThreadPriority = 2
    ThreadBasePriority = 3
    ThreadAffinityMask = 4
    ThreadImpersonationToken = 5
    ThreadDescriptorTableEntry = 6
    ThreadEnableAlignmentFaultFixup = 7
    ThreadEventPair = 8
    ThreadQuerySetWin32StartAddress = 9
    ThreadZeroTlsCell = 10
    ThreadPerformanceCount = 11
    ThreadAmILastThread = 12
    ThreadIdealProcessor = 13
    ThreadPriorityBoost = 14
    ThreadSetTlsArrayAddress = 15
    ThreadIsIoPending = 16
    ThreadHideFromDebugger = 17
    ThreadBreakOnTermination = 18
    ThreadSwitchLegacyState = 19
    ThreadIsTerminated = 20
    ThreadLastSystemCall = 21
    ThreadIoPriority = 22
    ThreadCycleTime = 23
    ThreadPagePriority = 24
    ThreadActualBasePriority = 25
    ThreadTebInformation = 26
    ThreadCSwitchMon = 27
    ThreadCSwitchPmu = 28
    ThreadWow64Context = 29
    ThreadGroupInformation = 30
    ThreadUmsInformation = 31
    ThreadCounterProfiling = 32
    ThreadIdealProcessorEx = 33
    ThreadCpuAccountingInformation = 34
    ThreadSuspendCount = 35
    ThreadHeterogeneousCpuPolicy = 36
    ThreadContainerId = 37
    ThreadNameInformation = 38
    ThreadSelectedCpuSets = 39
    ThreadSystemThreadInformation = 40
    ThreadActualGroupAffinity = 41
    ThreadDynamicCodePolicyInfo = 42
    ThreadExplicitCaseSensitivity = 43
    ThreadWorkOnBehalfTicket = 44
    ThreadSubsystemInformation = 45
    ThreadDbgkWerReportActive = 46
    ThreadAttachContainer = 47
    ThreadManageWritesToExecutableMemory = 48
    ThreadPowerThrottlingState = 49
    ThreadWorkloadClass = 50
    MaxThreadInfoClass = 51
make_global(THREADINFOCLASS)

class PROCESS_TLS_INFORMATION_TYPE(Enum):
    ProcessTlsReplaceIndex = 0
    ProcessTlsReplaceVector = 1
    MaxProcessTlsOperation = 2
make_global(PROCESS_TLS_INFORMATION_TYPE)

class PROCESS_WORKING_SET_OPERATION(Enum):
    ProcessWorkingSetSwap = 0
    ProcessWorkingSetEmpty = 1
    ProcessWorkingSetOperationMax = 2
make_global(PROCESS_WORKING_SET_OPERATION)

class PS_PROTECTED_TYPE(Enum):
    PsProtectedTypeNone = 0
    PsProtectedTypeProtectedLight = 1
    PsProtectedTypeProtected = 2
    PsProtectedTypeMax = 3
make_global(PS_PROTECTED_TYPE)

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
make_global(PS_PROTECTED_SIGNER)

class THREAD_UMS_INFORMATION_COMMAND(Enum):
    UmsInformationCommandInvalid = 0
    UmsInformationCommandAttach = 1
    UmsInformationCommandDetach = 2
    UmsInformationCommandQuery = 3
make_global(THREAD_UMS_INFORMATION_COMMAND)

class SUBSYSTEM_INFORMATION_TYPE(Enum):
    SubsystemInformationTypeWin32 = 0
    SubsystemInformationTypeWSL = 1
    MaxSubsystemInformationType = 2
make_global(SUBSYSTEM_INFORMATION_TYPE)

class THREAD_WORKLOAD_CLASS(Enum):
    ThreadWorkloadClassDefault = 0
    ThreadWorkloadClassGraphics = 1
    MaxThreadWorkloadClass = 2
make_global(THREAD_WORKLOAD_CLASS)

class PS_ATTRIBUTE_NUM(Enum):
    PsAttributeParentProcess = 0
    PsAttributeDebugPort = 1
    PsAttributeToken = 2
    PsAttributeClientId = 3
    PsAttributeTebAddress = 4
    PsAttributeImageName = 5
    PsAttributeImageInfo = 6
    PsAttributeMemoryReserve = 7
    PsAttributePriorityClass = 8
    PsAttributeErrorMode = 9
    PsAttributeStdHandleInfo = 10
    PsAttributeHandleList = 11
    PsAttributeGroupAffinity = 12
    PsAttributePreferredNode = 13
    PsAttributeIdealProcessor = 14
    PsAttributeUmsThread = 15
    PsAttributeMitigationOptions = 16
    PsAttributeProtectionLevel = 17
    PsAttributeSecureProcess = 18
    PsAttributeJobList = 19
    PsAttributeChildProcessPolicy = 20
    PsAttributeAllApplicationPackagesPolicy = 21
    PsAttributeWin32kFilter = 22
    PsAttributeSafeOpenPromptOriginClaim = 23
    PsAttributeBnoIsolation = 24
    PsAttributeDesktopAppPolicy = 25
    PsAttributeChpe = 26
    PsAttributeMax = 27
make_global(PS_ATTRIBUTE_NUM)

class PS_STD_HANDLE_STATE(Enum):
    PsNeverDuplicate = 0
    PsRequestDuplicate = 1
    PsAlwaysDuplicate = 2
    PsMaxStdHandleStates = 3
make_global(PS_STD_HANDLE_STATE)

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
    PS_MITIGATION_OPTION_ROP_STACKPIVOT = 20
    PS_MITIGATION_OPTION_ROP_CALLER_CHECK = 21
    PS_MITIGATION_OPTION_ROP_SIMEXEC = 22
    PS_MITIGATION_OPTION_EXPORT_ADDRESS_FILTER = 23
    PS_MITIGATION_OPTION_EXPORT_ADDRESS_FILTER_PLUS = 24
    PS_MITIGATION_OPTION_RESTRICT_CHILD_PROCESS_CREATION = 25
    PS_MITIGATION_OPTION_IMPORT_ADDRESS_FILTER = 26
    PS_MITIGATION_OPTION_MODULE_TAMPERING_PROTECTION = 27
    PS_MITIGATION_OPTION_RESTRICT_INDIRECT_BRANCH_PREDICTION = 28
    PS_MITIGATION_OPTION_SPECULATIVE_STORE_BYPASS_DISABLE = 29
    PS_MITIGATION_OPTION_ALLOW_DOWNGRADE_DYNAMIC_CODE_POLICY = 30
    PS_MITIGATION_OPTION_CET_SHADOW_STACKS = 31
make_global(PS_MITIGATION_OPTION)

class PS_CREATE_STATE(Enum):
    PsCreateInitialState = 0
    PsCreateFailOnFileOpen = 1
    PsCreateFailOnSectionCreate = 2
    PsCreateFailExeFormat = 3
    PsCreateFailMachineMismatch = 4
    PsCreateFailExeName = 5
    PsCreateSuccess = 6
    PsCreateMaximumStates = 7
make_global(PS_CREATE_STATE)

class MEMORY_RESERVE_TYPE(Enum):
    MemoryReserveUserApc = 0
    MemoryReserveIoCompletion = 1
    MemoryReserveTypeMax = 2
make_global(MEMORY_RESERVE_TYPE)

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
make_global(DBG_STATE)

class DEBUGOBJECTINFOCLASS(Enum):
    DebugObjectUnusedInformation = 0
    DebugObjectKillProcessOnExitInformation = 1
    MaxDebugObjectInfoClass = 2
make_global(DEBUGOBJECTINFOCLASS)

class FILE_INFORMATION_CLASS(Enum):
    FileDirectoryInformation = 1
    FileFullDirectoryInformation = 2
    FileBothDirectoryInformation = 3
    FileBasicInformation = 4
    FileStandardInformation = 5
    FileInternalInformation = 6
    FileEaInformation = 7
    FileAccessInformation = 8
    FileNameInformation = 9
    FileRenameInformation = 10
    FileLinkInformation = 11
    FileNamesInformation = 12
    FileDispositionInformation = 13
    FilePositionInformation = 14
    FileFullEaInformation = 15
    FileModeInformation = 16
    FileAlignmentInformation = 17
    FileAllInformation = 18
    FileAllocationInformation = 19
    FileEndOfFileInformation = 20
    FileAlternateNameInformation = 21
    FileStreamInformation = 22
    FilePipeInformation = 23
    FilePipeLocalInformation = 24
    FilePipeRemoteInformation = 25
    FileMailslotQueryInformation = 26
    FileMailslotSetInformation = 27
    FileCompressionInformation = 28
    FileObjectIdInformation = 29
    FileCompletionInformation = 30
    FileMoveClusterInformation = 31
    FileQuotaInformation = 32
    FileReparsePointInformation = 33
    FileNetworkOpenInformation = 34
    FileAttributeTagInformation = 35
    FileTrackingInformation = 36
    FileIdBothDirectoryInformation = 37
    FileIdFullDirectoryInformation = 38
    FileValidDataLengthInformation = 39
    FileShortNameInformation = 40
    FileIoCompletionNotificationInformation = 41
    FileIoStatusBlockRangeInformation = 42
    FileIoPriorityHintInformation = 43
    FileSfioReserveInformation = 44
    FileSfioVolumeInformation = 45
    FileHardLinkInformation = 46
    FileProcessIdsUsingFileInformation = 47
    FileNormalizedNameInformation = 48
    FileNetworkPhysicalNameInformation = 49
    FileIdGlobalTxDirectoryInformation = 50
    FileIsRemoteDeviceInformation = 51
    FileUnusedInformation = 52
    FileNumaNodeInformation = 53
    FileStandardLinkInformation = 54
    FileRemoteProtocolInformation = 55
    FileRenameInformationBypassAccessCheck = 56
    FileLinkInformationBypassAccessCheck = 57
    FileVolumeNameInformation = 58
    FileIdInformation = 59
    FileIdExtdDirectoryInformation = 60
    FileReplaceCompletionInformation = 61
    FileHardLinkFullIdInformation = 62
    FileIdExtdBothDirectoryInformation = 63
    FileDispositionInformationEx = 64
    FileRenameInformationEx = 65
    FileRenameInformationExBypassAccessCheck = 66
    FileDesiredStorageClassInformation = 67
    FileStatInformation = 68
    FileMemoryPartitionInformation = 69
    FileStatLxInformation = 70
    FileCaseSensitiveInformation = 71
    FileLinkInformationEx = 72
    FileLinkInformationExBypassAccessCheck = 73
    FileStorageReserveIdInformation = 74
    FileCaseSensitiveInformationForceAccessCheck = 75
    FileMaximumInformation = 76
make_global(FILE_INFORMATION_CLASS)

class IO_PRIORITY_HINT(Enum):
    IoPriorityVeryLow = 0
    IoPriorityLow = 1
    IoPriorityNormal = 2
    IoPriorityHigh = 3
    IoPriorityCritical = 4
    MaxIoPriorityTypes = 5
make_global(IO_PRIORITY_HINT)

class FSINFOCLASS(Enum):
    FileFsVolumeInformation = 1
    FileFsLabelInformation = 2
    FileFsSizeInformation = 3
    FileFsDeviceInformation = 4
    FileFsAttributeInformation = 5
    FileFsControlInformation = 6
    FileFsFullSizeInformation = 7
    FileFsObjectIdInformation = 8
    FileFsDriverPathInformation = 9
    FileFsVolumeFlagsInformation = 10
    FileFsSectorSizeInformation = 11
    FileFsDataCopyInformation = 12
    FileFsMetadataSizeInformation = 13
    FileFsFullSizeInformationEx = 14
    FileFsMaximumInformation = 15
make_global(FSINFOCLASS)

class DIRECTORY_NOTIFY_INFORMATION_CLASS(Enum):
    DirectoryNotifyInformation = 0
    DirectoryNotifyExtendedInformation = 1
make_global(DIRECTORY_NOTIFY_INFORMATION_CLASS)

class IO_COMPLETION_INFORMATION_CLASS(Enum):
    IoCompletionBasicInformation = 0
make_global(IO_COMPLETION_INFORMATION_CLASS)

class IO_SESSION_EVENT(Enum):
    IoSessionEventIgnore = 0
    IoSessionEventCreated = 1
    IoSessionEventTerminated = 2
    IoSessionEventConnected = 3
    IoSessionEventDisconnected = 4
    IoSessionEventLogon = 5
    IoSessionEventLogoff = 6
    IoSessionEventMax = 7
make_global(IO_SESSION_EVENT)

class IO_SESSION_STATE(Enum):
    IoSessionStateCreated = 0
    IoSessionStateInitialized = 1
    IoSessionStateConnected = 2
    IoSessionStateDisconnected = 3
    IoSessionStateDisconnectedLoggedOn = 4
    IoSessionStateLoggedOn = 5
    IoSessionStateLoggedOff = 6
    IoSessionStateTerminated = 7
    IoSessionStateMax = 8
make_global(IO_SESSION_STATE)

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
    MaximumInterfaceType = 17
make_global(INTERFACE_TYPE)

class DMA_WIDTH(Enum):
    Width8Bits = 0
    Width16Bits = 1
    Width32Bits = 2
    MaximumDmaWidth = 3
make_global(DMA_WIDTH)

class DMA_SPEED(Enum):
    Compatible = 0
    TypeA = 1
    TypeB = 2
    TypeC = 3
    TypeF = 4
    MaximumDmaSpeed = 5
make_global(DMA_SPEED)

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
make_global(BUS_DATA_TYPE)

class PORT_INFORMATION_CLASS(Enum):
    PortBasicInformation = 0
    PortDumpInformation = 1
make_global(PORT_INFORMATION_CLASS)

class ALPC_PORT_INFORMATION_CLASS(Enum):
    AlpcBasicInformation = 0
    AlpcPortInformation = 1
    AlpcAssociateCompletionPortInformation = 2
    AlpcConnectedSIDInformation = 3
    AlpcServerInformation = 4
    AlpcMessageZoneInformation = 5
    AlpcRegisterCompletionListInformation = 6
    AlpcUnregisterCompletionListInformation = 7
    AlpcAdjustCompletionListConcurrencyCountInformation = 8
    AlpcRegisterCallbackInformation = 9
    AlpcCompletionListRundownInformation = 10
    AlpcWaitForPortReferences = 11
make_global(ALPC_PORT_INFORMATION_CLASS)

class ALPC_MESSAGE_INFORMATION_CLASS(Enum):
    AlpcMessageSidInformation = 0
    AlpcMessageTokenModifiedIdInformation = 1
    AlpcMessageDirectStatusInformation = 2
    AlpcMessageHandleInformation = 3
    MaxAlpcMessageInfoClass = 4
make_global(ALPC_MESSAGE_INFORMATION_CLASS)

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
make_global(PF_BOOT_PHASE_ID)

class PF_ENABLE_STATUS(Enum):
    PfSvNotSpecified = 0
    PfSvEnabled = 1
    PfSvDisabled = 2
    PfSvMaxEnableStatus = 3
make_global(PF_ENABLE_STATUS)

class PREFETCHER_INFORMATION_CLASS(Enum):
    PrefetcherRetrieveTrace = 1
    PrefetcherSystemParameters = 2
    PrefetcherBootPhase = 3
    PrefetcherRetrieveBootLoaderTrace = 4
    PrefetcherBootControl = 5
make_global(PREFETCHER_INFORMATION_CLASS)

class PFS_PRIVATE_PAGE_SOURCE_TYPE(Enum):
    PfsPrivateSourceKernel = 0
    PfsPrivateSourceSession = 1
    PfsPrivateSourceProcess = 2
    PfsPrivateSourceMax = 3
make_global(PFS_PRIVATE_PAGE_SOURCE_TYPE)

class PF_PHASED_SCENARIO_TYPE(Enum):
    PfScenarioTypeNone = 0
    PfScenarioTypeStandby = 1
    PfScenarioTypeHibernate = 2
    PfScenarioTypeFUS = 3
    PfScenarioTypeMax = 4
make_global(PF_PHASED_SCENARIO_TYPE)

class SUPERFETCH_INFORMATION_CLASS(Enum):
    SuperfetchRetrieveTrace = 1
    SuperfetchSystemParameters = 2
    SuperfetchLogEvent = 3
    SuperfetchGenerateTrace = 4
    SuperfetchPrefetch = 5
    SuperfetchPfnQuery = 6
    SuperfetchPfnSetPriority = 7
    SuperfetchPrivSourceQuery = 8
    SuperfetchSequenceNumberQuery = 9
    SuperfetchScenarioPhase = 10
    SuperfetchWorkerPriority = 11
    SuperfetchScenarioQuery = 12
    SuperfetchScenarioPrefetch = 13
    SuperfetchRobustnessControl = 14
    SuperfetchTimeControl = 15
    SuperfetchMemoryListQuery = 16
    SuperfetchMemoryRangesQuery = 17
    SuperfetchTracingControl = 18
    SuperfetchTrimWhileAgingControl = 19
    SuperfetchRepurposedByPrefetch = 20
    SuperfetchInformationMax = 21
make_global(SUPERFETCH_INFORMATION_CLASS)

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
make_global(PLUGPLAY_EVENT_CATEGORY)

class PLUGPLAY_CONTROL_CLASS(Enum):
    PlugPlayControlEnumerateDevice = 0
    PlugPlayControlRegisterNewDevice = 1
    PlugPlayControlDeregisterDevice = 2
    PlugPlayControlInitializeDevice = 3
    PlugPlayControlStartDevice = 4
    PlugPlayControlUnlockDevice = 5
    PlugPlayControlQueryAndRemoveDevice = 6
    PlugPlayControlUserResponse = 7
    PlugPlayControlGenerateLegacyDevice = 8
    PlugPlayControlGetInterfaceDeviceList = 9
    PlugPlayControlProperty = 10
    PlugPlayControlDeviceClassAssociation = 11
    PlugPlayControlGetRelatedDevice = 12
    PlugPlayControlGetInterfaceDeviceAlias = 13
    PlugPlayControlDeviceStatus = 14
    PlugPlayControlGetDeviceDepth = 15
    PlugPlayControlQueryDeviceRelations = 16
    PlugPlayControlTargetDeviceRelation = 17
    PlugPlayControlQueryConflictList = 18
    PlugPlayControlRetrieveDock = 19
    PlugPlayControlResetDevice = 20
    PlugPlayControlHaltDevice = 21
    PlugPlayControlGetBlockedDriverList = 22
    PlugPlayControlGetDeviceInterfaceEnabled = 23
    MaxPlugPlayControl = 24
make_global(PLUGPLAY_CONTROL_CLASS)

class POWER_STATE_TYPE(Enum):
    SystemPowerState = 0
    DevicePowerState = 1
make_global(POWER_STATE_TYPE)

class POWER_STATE_HANDLER_TYPE(Enum):
    PowerStateSleeping1 = 0
    PowerStateSleeping2 = 1
    PowerStateSleeping3 = 2
    PowerStateSleeping4 = 3
    PowerStateShutdownOff = 4
    PowerStateShutdownReset = 5
    PowerStateSleeping4Firmware = 6
    PowerStateMaximum = 7
make_global(POWER_STATE_HANDLER_TYPE)

class POWER_REQUEST_ORIGIN(Enum):
    POWER_REQUEST_ORIGIN_DRIVER = 0
    POWER_REQUEST_ORIGIN_PROCESS = 1
    POWER_REQUEST_ORIGIN_SERVICE = 2
make_global(POWER_REQUEST_ORIGIN)

class KEY_INFORMATION_CLASS(Enum):
    KeyBasicInformation = 0
    KeyNodeInformation = 1
    KeyFullInformation = 2
    KeyNameInformation = 3
    KeyCachedInformation = 4
    KeyFlagsInformation = 5
    KeyVirtualizationInformation = 6
    KeyHandleTagsInformation = 7
    KeyTrustInformation = 8
    KeyLayerInformation = 9
    MaxKeyInfoClass = 10
make_global(KEY_INFORMATION_CLASS)

class KEY_SET_INFORMATION_CLASS(Enum):
    KeyWriteTimeInformation = 0
    KeyWow64FlagsInformation = 1
    KeyControlFlagsInformation = 2
    KeySetVirtualizationInformation = 3
    KeySetDebugInformation = 4
    KeySetHandleTagsInformation = 5
    KeySetLayerInformation = 6
    MaxKeySetInfoClass = 7
make_global(KEY_SET_INFORMATION_CLASS)

class KEY_VALUE_INFORMATION_CLASS(Enum):
    KeyValueBasicInformation = 0
    KeyValueFullInformation = 1
    KeyValuePartialInformation = 2
    KeyValueFullInformationAlign64 = 3
    KeyValuePartialInformationAlign64 = 4
    KeyValueLayerInformation = 5
    MaxKeyValueInfoClass = 6
make_global(KEY_VALUE_INFORMATION_CLASS)

class REG_ACTION(Enum):
    KeyAdded = 0
    KeyRemoved = 1
    KeyModified = 2
make_global(REG_ACTION)

class TABLE_SEARCH_RESULT(Enum):
    TableEmptyTree = 0
    TableFoundNode = 1
    TableInsertAsLeft = 2
    TableInsertAsRight = 3
make_global(TABLE_SEARCH_RESULT)

class RTL_GENERIC_COMPARE_RESULTS(Enum):
    GenericLessThan = 0
    GenericGreaterThan = 1
    GenericEqual = 2
make_global(RTL_GENERIC_COMPARE_RESULTS)

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
make_global(RTL_NORM_FORM)

class FUNCTION_TABLE_TYPE(Enum):
    RF_SORTED = 0
    RF_UNSORTED = 1
    RF_CALLBACK = 2
    RF_KERNEL_DYNAMIC = 3
make_global(FUNCTION_TABLE_TYPE)

class RTL_PATH_TYPE(Enum):
    RtlPathTypeUnknown = 0
    RtlPathTypeUncAbsolute = 1
    RtlPathTypeDriveAbsolute = 2
    RtlPathTypeDriveRelative = 3
    RtlPathTypeRooted = 4
    RtlPathTypeRelative = 5
    RtlPathTypeLocalDevice = 6
    RtlPathTypeRootLocalDevice = 7
make_global(RTL_PATH_TYPE)

class HEAP_COMPATIBILITY_MODE(Enum):
    HEAP_COMPATIBILITY_STANDARD = 0
    HEAP_COMPATIBILITY_LAL = 1
    HEAP_COMPATIBILITY_LFH = 2
make_global(HEAP_COMPATIBILITY_MODE)

class IMAGE_MITIGATION_POLICY(Enum):
    ImageDepPolicy = 0
    ImageAslrPolicy = 1
    ImageDynamicCodePolicy = 2
    ImageStrictHandleCheckPolicy = 3
    ImageSystemCallDisablePolicy = 4
    ImageMitigationOptionsMask = 5
    ImageExtensionPointDisablePolicy = 6
    ImageControlFlowGuardPolicy = 7
    ImageSignaturePolicy = 8
    ImageFontDisablePolicy = 9
    ImageImageLoadPolicy = 10
    ImagePayloadRestrictionPolicy = 11
    ImageChildProcessPolicy = 12
    ImageSehopPolicy = 13
    ImageHeapPolicy = 14
    MaxImageMitigationPolicy = 15
make_global(IMAGE_MITIGATION_POLICY)

class RTL_IMAGE_MITIGATION_OPTION_STATE(Enum):
    RtlMitigationOptionStateNotConfigured = 0
    RtlMitigationOptionStateOn = 1
    RtlMitigationOptionStateOff = 2
make_global(RTL_IMAGE_MITIGATION_OPTION_STATE)

class APPCONTAINER_SID_TYPE(Enum):
    NotAppContainerSidType = 0
    ChildAppContainerSidType = 1
    ParentAppContainerSidType = 2
    InvalidAppContainerSidType = 3
    MaxAppContainerSidType = 4
make_global(APPCONTAINER_SID_TYPE)

class STATE_LOCATION_TYPE(Enum):
    LocationTypeRegistry = 0
    LocationTypeFileSystem = 1
    LocationTypeMaximum = 2
make_global(STATE_LOCATION_TYPE)

class RTL_BSD_ITEM_TYPE(Enum):
    RtlBsdItemVersionNumber = 0
    RtlBsdItemProductType = 1
    RtlBsdItemAabEnabled = 2
    RtlBsdItemAabTimeout = 3
    RtlBsdItemBootGood = 4
    RtlBsdItemBootShutdown = 5
    RtlBsdSleepInProgress = 6
    RtlBsdPowerTransition = 7
    RtlBsdItemBootAttemptCount = 8
    RtlBsdItemBootCheckpoint = 9
    RtlBsdItemBootId = 10
    RtlBsdItemShutdownBootId = 11
    RtlBsdItemReportedAbnormalShutdownBootId = 12
    RtlBsdItemErrorInfo = 13
    RtlBsdItemPowerButtonPressInfo = 14
    RtlBsdItemChecksum = 15
    RtlBsdPowerTransitionExtension = 16
    RtlBsdItemFeatureConfigurationState = 17
    RtlBsdItemMax = 18
make_global(RTL_BSD_ITEM_TYPE)

class TP_TRACE_TYPE(Enum):
    TpTraceThreadPriority = 1
    TpTraceThreadAffinity = 2
    MaxTpTraceType = 3
make_global(TP_TRACE_TYPE)

class KMTQUERYADAPTERINFOTYPE(Enum):
    KMTQAITYPE_UMDRIVERPRIVATE = 0
    KMTQAITYPE_UMDRIVERNAME = 1
    KMTQAITYPE_UMOPENGLINFO = 2
    KMTQAITYPE_GETSEGMENTSIZE = 3
    KMTQAITYPE_ADAPTERGUID = 4
    KMTQAITYPE_FLIPQUEUEINFO = 5
    KMTQAITYPE_ADAPTERADDRESS = 6
    KMTQAITYPE_SETWORKINGSETINFO = 7
    KMTQAITYPE_ADAPTERREGISTRYINFO = 8
    KMTQAITYPE_CURRENTDISPLAYMODE = 9
    KMTQAITYPE_MODELIST = 10
    KMTQAITYPE_CHECKDRIVERUPDATESTATUS = 11
    KMTQAITYPE_VIRTUALADDRESSINFO = 12
    KMTQAITYPE_DRIVERVERSION = 13
    KMTQAITYPE_UNKNOWN = 14
    KMTQAITYPE_ADAPTERTYPE = 15
    KMTQAITYPE_OUTPUTDUPLCONTEXTSCOUNT = 16
    KMTQAITYPE_WDDM_1_2_CAPS = 17
    KMTQAITYPE_UMD_DRIVER_VERSION = 18
    KMTQAITYPE_DIRECTFLIP_SUPPORT = 19
    KMTQAITYPE_MULTIPLANEOVERLAY_SUPPORT = 20
    KMTQAITYPE_DLIST_DRIVER_NAME = 21
    KMTQAITYPE_WDDM_1_3_CAPS = 22
    KMTQAITYPE_MULTIPLANEOVERLAY_HUD_SUPPORT = 23
    KMTQAITYPE_WDDM_2_0_CAPS = 24
    KMTQAITYPE_NODEMETADATA = 25
    KMTQAITYPE_CPDRIVERNAME = 26
    KMTQAITYPE_XBOX = 27
    KMTQAITYPE_INDEPENDENTFLIP_SUPPORT = 28
    KMTQAITYPE_MIRACASTCOMPANIONDRIVERNAME = 29
    KMTQAITYPE_PHYSICALADAPTERCOUNT = 30
    KMTQAITYPE_PHYSICALADAPTERDEVICEIDS = 31
    KMTQAITYPE_DRIVERCAPS_EXT = 32
    KMTQAITYPE_QUERY_MIRACAST_DRIVER_TYPE = 33
    KMTQAITYPE_QUERY_GPUMMU_CAPS = 34
    KMTQAITYPE_QUERY_MULTIPLANEOVERLAY_DECODE_SUPPORT = 35
    KMTQAITYPE_QUERY_HW_PROTECTION_TEARDOWN_COUNT = 36
    KMTQAITYPE_QUERY_ISBADDRIVERFORHWPROTECTIONDISABLED = 37
    KMTQAITYPE_MULTIPLANEOVERLAY_SECONDARY_SUPPORT = 38
    KMTQAITYPE_INDEPENDENTFLIP_SECONDARY_SUPPORT = 39
    KMTQAITYPE_PANELFITTER_SUPPORT = 40
    KMTQAITYPE_PHYSICALADAPTERPNPKEY = 41
    KMTQAITYPE_GETSEGMENTGROUPSIZE = 42
    KMTQAITYPE_MPO3DDI_SUPPORT = 43
    KMTQAITYPE_HWDRM_SUPPORT = 44
    KMTQAITYPE_MPOKERNELCAPS_SUPPORT = 45
    KMTQAITYPE_MULTIPLANEOVERLAY_STRETCH_SUPPORT = 46
    KMTQAITYPE_GET_DEVICE_VIDPN_OWNERSHIP_INFO = 47
    KMTQAITYPE_QUERYREGISTRY = 48
    KMTQAITYPE_KMD_DRIVER_VERSION = 49
    KMTQAITYPE_BLOCKLIST_KERNEL = 50
    KMTQAITYPE_BLOCKLIST_RUNTIME = 51
    KMTQAITYPE_ADAPTERGUID_RENDER = 52
    KMTQAITYPE_ADAPTERADDRESS_RENDER = 53
    KMTQAITYPE_ADAPTERREGISTRYINFO_RENDER = 54
    KMTQAITYPE_CHECKDRIVERUPDATESTATUS_RENDER = 55
    KMTQAITYPE_DRIVERVERSION_RENDER = 56
    KMTQAITYPE_ADAPTERTYPE_RENDER = 57
    KMTQAITYPE_WDDM_1_2_CAPS_RENDER = 58
    KMTQAITYPE_WDDM_1_3_CAPS_RENDER = 59
    KMTQAITYPE_QUERY_ADAPTER_UNIQUE_GUID = 60
    KMTQAITYPE_NODEPERFDATA = 61
    KMTQAITYPE_ADAPTERPERFDATA = 62
    KMTQAITYPE_ADAPTERPERFDATA_CAPS = 63
    KMTQUITYPE_GPUVERSION = 64
    KMTQAITYPE_DRIVER_DESCRIPTION = 65
    KMTQAITYPE_DRIVER_DESCRIPTION_RENDER = 66
    KMTQAITYPE_SCANOUT_CAPS = 67
    KMTQAITYPE_DISPLAY_UMDRIVERNAME = 68
    KMTQAITYPE_PARAVIRTUALIZATION_RENDER = 69
    KMTQAITYPE_SERVICENAME = 70
    KMTQAITYPE_WDDM_2_7_CAPS = 71
    KMTQAITYPE_TRACKEDWORKLOAD_SUPPORT = 72
make_global(KMTQUERYADAPTERINFOTYPE)

class KMTUMDVERSION(Enum):
    KMTUMDVERSION_DX9 = 0
    KMTUMDVERSION_DX10 = 1
    KMTUMDVERSION_DX11 = 2
    KMTUMDVERSION_DX12 = 3
    NUM_KMTUMDVERSIONS = 4
make_global(KMTUMDVERSION)

class D3DDDIFORMAT(Enum):
    D3DDDIFMT_UNKNOWN = 0
    D3DDDIFMT_R8G8B8 = 20
    D3DDDIFMT_A8R8G8B8 = 21
    D3DDDIFMT_X8R8G8B8 = 22
    D3DDDIFMT_R5G6B5 = 23
    D3DDDIFMT_X1R5G5B5 = 24
    D3DDDIFMT_A1R5G5B5 = 25
    D3DDDIFMT_A4R4G4B4 = 26
    D3DDDIFMT_R3G3B2 = 27
    D3DDDIFMT_A8 = 28
    D3DDDIFMT_A8R3G3B2 = 29
    D3DDDIFMT_X4R4G4B4 = 30
    D3DDDIFMT_A2B10G10R10 = 31
    D3DDDIFMT_A8B8G8R8 = 32
    D3DDDIFMT_X8B8G8R8 = 33
    D3DDDIFMT_G16R16 = 34
    D3DDDIFMT_A2R10G10B10 = 35
    D3DDDIFMT_A16B16G16R16 = 36
    D3DDDIFMT_A8P8 = 40
    D3DDDIFMT_P8 = 41
    D3DDDIFMT_L8 = 50
    D3DDDIFMT_A8L8 = 51
    D3DDDIFMT_A4L4 = 52
    D3DDDIFMT_V8U8 = 60
    D3DDDIFMT_L6V5U5 = 61
    D3DDDIFMT_X8L8V8U8 = 62
    D3DDDIFMT_Q8W8V8U8 = 63
    D3DDDIFMT_V16U16 = 64
    D3DDDIFMT_W11V11U10 = 65
    D3DDDIFMT_A2W10V10U10 = 67
    D3DDDIFMT_UYVY = 1498831189
    D3DDDIFMT_R8G8_B8G8 = 1195525970
    D3DDDIFMT_YUY2 = 844715353
    D3DDDIFMT_G8R8_G8B8 = 1111970375
    D3DDDIFMT_DXT1 = 827611204
    D3DDDIFMT_DXT2 = 844388420
    D3DDDIFMT_DXT3 = 861165636
    D3DDDIFMT_DXT4 = 877942852
    D3DDDIFMT_DXT5 = 894720068
    D3DDDIFMT_D16_LOCKABLE = 70
    D3DDDIFMT_D32 = 71
    D3DDDIFMT_D15S1 = 73
    D3DDDIFMT_D24S8 = 75
    D3DDDIFMT_D24X8 = 77
    D3DDDIFMT_D24X4S4 = 79
    D3DDDIFMT_D16 = 80
    D3DDDIFMT_D32F_LOCKABLE = 82
    D3DDDIFMT_D24FS8 = 83
    D3DDDIFMT_D32_LOCKABLE = 84
    D3DDDIFMT_S8_LOCKABLE = 85
    D3DDDIFMT_S1D15 = 72
    D3DDDIFMT_S8D24 = 74
    D3DDDIFMT_X8D24 = 76
    D3DDDIFMT_X4S4D24 = 78
    D3DDDIFMT_L16 = 81
    D3DDDIFMT_G8R8 = 91
    D3DDDIFMT_R8 = 92
    D3DDDIFMT_VERTEXDATA = 100
    D3DDDIFMT_INDEX16 = 101
    D3DDDIFMT_INDEX32 = 102
    D3DDDIFMT_Q16W16V16U16 = 110
    D3DDDIFMT_MULTI2_ARGB8 = 827606349
    D3DDDIFMT_R16F = 111
    D3DDDIFMT_G16R16F = 112
    D3DDDIFMT_A16B16G16R16F = 113
    D3DDDIFMT_R32F = 114
    D3DDDIFMT_G32R32F = 115
    D3DDDIFMT_A32B32G32R32F = 116
    D3DDDIFMT_CxV8U8 = 117
    D3DDDIFMT_A1 = 118
    D3DDDIFMT_A2B10G10R10_XR_BIAS = 119
    D3DDDIFMT_DXVACOMPBUFFER_BASE = 150
    D3DDDIFMT_PICTUREPARAMSDATA = 150
    D3DDDIFMT_MACROBLOCKDATA = 151
    D3DDDIFMT_RESIDUALDIFFERENCEDATA = 152
    D3DDDIFMT_DEBLOCKINGDATA = 153
    D3DDDIFMT_INVERSEQUANTIZATIONDATA = 154
    D3DDDIFMT_SLICECONTROLDATA = 155
    D3DDDIFMT_BITSTREAMDATA = 156
    D3DDDIFMT_MOTIONVECTORBUFFER = 157
    D3DDDIFMT_FILMGRAINBUFFER = 158
    D3DDDIFMT_DXVA_RESERVED9 = 159
    D3DDDIFMT_DXVA_RESERVED10 = 160
    D3DDDIFMT_DXVA_RESERVED11 = 161
    D3DDDIFMT_DXVA_RESERVED12 = 162
    D3DDDIFMT_DXVA_RESERVED13 = 163
    D3DDDIFMT_DXVA_RESERVED14 = 164
    D3DDDIFMT_DXVA_RESERVED15 = 165
    D3DDDIFMT_DXVA_RESERVED16 = 166
    D3DDDIFMT_DXVA_RESERVED17 = 167
    D3DDDIFMT_DXVA_RESERVED18 = 168
    D3DDDIFMT_DXVA_RESERVED19 = 169
    D3DDDIFMT_DXVA_RESERVED20 = 170
    D3DDDIFMT_DXVA_RESERVED21 = 171
    D3DDDIFMT_DXVA_RESERVED22 = 172
    D3DDDIFMT_DXVA_RESERVED23 = 173
    D3DDDIFMT_DXVA_RESERVED24 = 174
    D3DDDIFMT_DXVA_RESERVED25 = 175
    D3DDDIFMT_DXVA_RESERVED26 = 176
    D3DDDIFMT_DXVA_RESERVED27 = 177
    D3DDDIFMT_DXVA_RESERVED28 = 178
    D3DDDIFMT_DXVA_RESERVED29 = 179
    D3DDDIFMT_DXVA_RESERVED30 = 180
    D3DDDIFMT_DXVA_RESERVED31 = 181
    D3DDDIFMT_DXVACOMPBUFFER_MAX = 181
    D3DDDIFMT_BINARYBUFFER = 199
    D3DDDIFMT_FORCE_UINT = 2147483647
make_global(D3DDDIFORMAT)

class D3DDDI_VIDEO_SIGNAL_SCANLINE_ORDERING(Enum):
    D3DDDI_VSSLO_UNINITIALIZED = 0
    D3DDDI_VSSLO_PROGRESSIVE = 1
    D3DDDI_VSSLO_INTERLACED_UPPERFIELDFIRST = 2
    D3DDDI_VSSLO_INTERLACED_LOWERFIELDFIRST = 3
    D3DDDI_VSSLO_OTHER = 255
make_global(D3DDDI_VIDEO_SIGNAL_SCANLINE_ORDERING)

class D3DDDI_ROTATION(Enum):
    D3DDDI_ROTATION_IDENTITY = 1
    D3DDDI_ROTATION_90 = 2
    D3DDDI_ROTATION_180 = 3
    D3DDDI_ROTATION_270 = 4
make_global(D3DDDI_ROTATION)

class D3DKMDT_MODE_PRUNING_REASON(Enum):
    D3DKMDT_MPR_UNINITIALIZED = 0
    D3DKMDT_MPR_ALLCAPS = 1
    D3DKMDT_MPR_DESCRIPTOR_MONITOR_SOURCE_MODE = 2
    D3DKMDT_MPR_DESCRIPTOR_MONITOR_FREQUENCY_RANGE = 3
    D3DKMDT_MPR_DESCRIPTOR_OVERRIDE_MONITOR_SOURCE_MODE = 4
    D3DKMDT_MPR_DESCRIPTOR_OVERRIDE_MONITOR_FREQUENCY_RANGE = 5
    D3DKMDT_MPR_DEFAULT_PROFILE_MONITOR_SOURCE_MODE = 6
    D3DKMDT_MPR_DRIVER_RECOMMENDED_MONITOR_SOURCE_MODE = 7
    D3DKMDT_MPR_MONITOR_FREQUENCY_RANGE_OVERRIDE = 8
    D3DKMDT_MPR_CLONE_PATH_PRUNED = 9
    D3DKMDT_MPR_MAXVALID = 10
make_global(D3DKMDT_MODE_PRUNING_REASON)

class D3DKMT_DRIVERVERSION(Enum):
    KMT_DRIVERVERSION_WDDM_1_0 = 1000
    KMT_DRIVERVERSION_WDDM_1_1_PRERELEASE = 1102
    KMT_DRIVERVERSION_WDDM_1_1 = 1105
    KMT_DRIVERVERSION_WDDM_1_2 = 1200
    KMT_DRIVERVERSION_WDDM_1_3 = 1300
    KMT_DRIVERVERSION_WDDM_2_0 = 2000
    KMT_DRIVERVERSION_WDDM_2_1 = 2100
    KMT_DRIVERVERSION_WDDM_2_2 = 2200
    KMT_DRIVERVERSION_WDDM_2_3 = 2300
    KMT_DRIVERVERSION_WDDM_2_4 = 2400
    KMT_DRIVERVERSION_WDDM_2_5 = 2500
    KMT_DRIVERVERSION_WDDM_2_6 = 2600
    KMT_DRIVERVERSION_WDDM_2_7 = 2700
make_global(D3DKMT_DRIVERVERSION)

class D3DKMDT_GRAPHICS_PREEMPTION_GRANULARITY(Enum):
    D3DKMDT_GRAPHICS_PREEMPTION_NONE = 0
    D3DKMDT_GRAPHICS_PREEMPTION_DMA_BUFFER_BOUNDARY = 100
    D3DKMDT_GRAPHICS_PREEMPTION_PRIMITIVE_BOUNDARY = 200
    D3DKMDT_GRAPHICS_PREEMPTION_TRIANGLE_BOUNDARY = 300
    D3DKMDT_GRAPHICS_PREEMPTION_PIXEL_BOUNDARY = 400
    D3DKMDT_GRAPHICS_PREEMPTION_SHADER_BOUNDARY = 500
make_global(D3DKMDT_GRAPHICS_PREEMPTION_GRANULARITY)

class D3DKMDT_COMPUTE_PREEMPTION_GRANULARITY(Enum):
    D3DKMDT_COMPUTE_PREEMPTION_NONE = 0
    D3DKMDT_COMPUTE_PREEMPTION_DMA_BUFFER_BOUNDARY = 100
    D3DKMDT_COMPUTE_PREEMPTION_DISPATCH_BOUNDARY = 200
    D3DKMDT_COMPUTE_PREEMPTION_THREAD_GROUP_BOUNDARY = 300
    D3DKMDT_COMPUTE_PREEMPTION_THREAD_BOUNDARY = 400
    D3DKMDT_COMPUTE_PREEMPTION_SHADER_BOUNDARY = 500
make_global(D3DKMDT_COMPUTE_PREEMPTION_GRANULARITY)

class DXGK_ENGINE_TYPE(Enum):
    DXGK_ENGINE_TYPE_OTHER = 0
    DXGK_ENGINE_TYPE_3D = 1
    DXGK_ENGINE_TYPE_VIDEO_DECODE = 2
    DXGK_ENGINE_TYPE_VIDEO_ENCODE = 3
    DXGK_ENGINE_TYPE_VIDEO_PROCESSING = 4
    DXGK_ENGINE_TYPE_SCENE_ASSEMBLY = 5
    DXGK_ENGINE_TYPE_COPY = 6
    DXGK_ENGINE_TYPE_OVERLAY = 7
    DXGK_ENGINE_TYPE_CRYPTO = 8
    DXGK_ENGINE_TYPE_MAX = 9
make_global(DXGK_ENGINE_TYPE)

class D3DKMT_MIRACAST_DRIVER_TYPE(Enum):
    D3DKMT_MIRACAST_DRIVER_NOT_SUPPORTED = 0
    D3DKMT_MIRACAST_DRIVER_IHV = 1
    D3DKMT_MIRACAST_DRIVER_MS = 2
make_global(D3DKMT_MIRACAST_DRIVER_TYPE)

class D3DKMT_PNP_KEY_TYPE(Enum):
    D3DKMT_PNP_KEY_HARDWARE = 1
    D3DKMT_PNP_KEY_SOFTWARE = 2
make_global(D3DKMT_PNP_KEY_TYPE)

class D3DDDI_QUERYREGISTRY_TYPE(Enum):
    D3DDDI_QUERYREGISTRY_SERVICEKEY = 0
    D3DDDI_QUERYREGISTRY_ADAPTERKEY = 1
    D3DDDI_QUERYREGISTRY_DRIVERSTOREPATH = 2
    D3DDDI_QUERYREGISTRY_DRIVERIMAGEPATH = 3
    D3DDDI_QUERYREGISTRY_MAX = 4
make_global(D3DDDI_QUERYREGISTRY_TYPE)

class D3DDDI_QUERYREGISTRY_STATUS(Enum):
    D3DDDI_QUERYREGISTRY_STATUS_SUCCESS = 0
    D3DDDI_QUERYREGISTRY_STATUS_BUFFER_OVERFLOW = 1
    D3DDDI_QUERYREGISTRY_STATUS_FAIL = 2
    D3DDDI_QUERYREGISTRY_STATUS_MAX = 3
make_global(D3DDDI_QUERYREGISTRY_STATUS)

class D3DKMT_QUERYRESULT_PREEMPTION_ATTEMPT_RESULT(Enum):
    D3DKMT_PreemptionAttempt = 0
    D3DKMT_PreemptionAttemptSuccess = 1
    D3DKMT_PreemptionAttemptMissNoCommand = 2
    D3DKMT_PreemptionAttemptMissNotEnabled = 3
    D3DKMT_PreemptionAttemptMissNextFence = 4
    D3DKMT_PreemptionAttemptMissPagingCommand = 5
    D3DKMT_PreemptionAttemptMissSplittedCommand = 6
    D3DKMT_PreemptionAttemptMissFenceCommand = 7
    D3DKMT_PreemptionAttemptMissRenderPendingFlip = 8
    D3DKMT_PreemptionAttemptMissNotMakingProgress = 9
    D3DKMT_PreemptionAttemptMissLessPriority = 10
    D3DKMT_PreemptionAttemptMissRemainingQuantum = 11
    D3DKMT_PreemptionAttemptMissRemainingPreemptionQuantum = 12
    D3DKMT_PreemptionAttemptMissAlreadyPreempting = 13
    D3DKMT_PreemptionAttemptMissGlobalBlock = 14
    D3DKMT_PreemptionAttemptMissAlreadyRunning = 15
    D3DKMT_PreemptionAttemptStatisticsMax = 16
make_global(D3DKMT_QUERYRESULT_PREEMPTION_ATTEMPT_RESULT)

class D3DKMT_QUERYSTATISTICS_DMA_PACKET_TYPE(Enum):
    D3DKMT_ClientRenderBuffer = 0
    D3DKMT_ClientPagingBuffer = 1
    D3DKMT_SystemPagingBuffer = 2
    D3DKMT_SystemPreemptionBuffer = 3
    D3DKMT_DmaPacketTypeMax = 4
make_global(D3DKMT_QUERYSTATISTICS_DMA_PACKET_TYPE)

class D3DKMT_QUERYSTATISTICS_QUEUE_PACKET_TYPE(Enum):
    D3DKMT_RenderCommandBuffer = 0
    D3DKMT_DeferredCommandBuffer = 1
    D3DKMT_SystemCommandBuffer = 2
    D3DKMT_MmIoFlipCommandBuffer = 3
    D3DKMT_WaitCommandBuffer = 4
    D3DKMT_SignalCommandBuffer = 5
    D3DKMT_DeviceCommandBuffer = 6
    D3DKMT_SoftwareCommandBuffer = 7
    D3DKMT_QueuePacketTypeMax = 8
make_global(D3DKMT_QUERYSTATISTICS_QUEUE_PACKET_TYPE)

class D3DKMT_QUERYSTATISTICS_ALLOCATION_PRIORITY_CLASS(Enum):
    D3DKMT_AllocationPriorityClassMinimum = 0
    D3DKMT_AllocationPriorityClassLow = 1
    D3DKMT_AllocationPriorityClassNormal = 2
    D3DKMT_AllocationPriorityClassHigh = 3
    D3DKMT_AllocationPriorityClassMaximum = 4
    D3DKMT_MaxAllocationPriorityClass = 5
make_global(D3DKMT_QUERYSTATISTICS_ALLOCATION_PRIORITY_CLASS)

class D3DKMT_QUERYSTATISTICS_TYPE(Enum):
    D3DKMT_QUERYSTATISTICS_ADAPTER = 0
    D3DKMT_QUERYSTATISTICS_PROCESS = 1
    D3DKMT_QUERYSTATISTICS_PROCESS_ADAPTER = 2
    D3DKMT_QUERYSTATISTICS_SEGMENT = 3
    D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT = 4
    D3DKMT_QUERYSTATISTICS_NODE = 5
    D3DKMT_QUERYSTATISTICS_PROCESS_NODE = 6
    D3DKMT_QUERYSTATISTICS_VIDPNSOURCE = 7
    D3DKMT_QUERYSTATISTICS_PROCESS_VIDPNSOURCE = 8
    D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_GROUP = 9
    D3DKMT_QUERYSTATISTICS_PHYSICAL_ADAPTER = 10
make_global(D3DKMT_QUERYSTATISTICS_TYPE)

class D3DKMT_MEMORY_SEGMENT_GROUP(Enum):
    D3DKMT_MEMORY_SEGMENT_GROUP_LOCAL = 0
    D3DKMT_MEMORY_SEGMENT_GROUP_NON_LOCAL = 1
make_global(D3DKMT_MEMORY_SEGMENT_GROUP)

class D3DKMT_ESCAPETYPE(Enum):
    D3DKMT_ESCAPE_DRIVERPRIVATE = 0
    D3DKMT_ESCAPE_VIDMM = 1
    D3DKMT_ESCAPE_TDRDBGCTRL = 2
    D3DKMT_ESCAPE_VIDSCH = 3
    D3DKMT_ESCAPE_DEVICE = 4
    D3DKMT_ESCAPE_DMM = 5
    D3DKMT_ESCAPE_DEBUG_SNAPSHOT = 6
    D3DKMT_ESCAPE_DRT_TEST = 8
    D3DKMT_ESCAPE_DIAGNOSTICS = 9
    D3DKMT_ESCAPE_OUTPUTDUPL_SNAPSHOT = 10
    D3DKMT_ESCAPE_OUTPUTDUPL_DIAGNOSTICS = 11
    D3DKMT_ESCAPE_BDD_PNP = 12
    D3DKMT_ESCAPE_BDD_FALLBACK = 13
    D3DKMT_ESCAPE_ACTIVATE_SPECIFIC_DIAG = 14
    D3DKMT_ESCAPE_MODES_PRUNED_OUT = 15
    D3DKMT_ESCAPE_WHQL_INFO = 16
    D3DKMT_ESCAPE_BRIGHTNESS = 17
    D3DKMT_ESCAPE_EDID_CACHE = 18
    D3DKMT_ESCAPE_GENERIC_ADAPTER_DIAG_INFO = 19
    D3DKMT_ESCAPE_MIRACAST_DISPLAY_REQUEST = 20
    D3DKMT_ESCAPE_HISTORY_BUFFER_STATUS = 21
    D3DKMT_ESCAPE_MIRACAST_ADAPTER_DIAG_INFO = 23
    D3DKMT_ESCAPE_FORCE_BDDFALLBACK_HEADLESS = 24
    D3DKMT_ESCAPE_REQUEST_MACHINE_CRASH = 25
    D3DKMT_ESCAPE_HMD_GET_EDID_BASE_BLOCK = 26
    D3DKMT_ESCAPE_SOFTGPU_ENABLE_DISABLE_HMD = 27
    D3DKMT_ESCAPE_PROCESS_VERIFIER_OPTION = 28
    D3DKMT_ESCAPE_ADAPTER_VERIFIER_OPTION = 29
    D3DKMT_ESCAPE_IDD_REQUEST = 30
    D3DKMT_ESCAPE_DOD_SET_DIRTYRECT_MODE = 31
    D3DKMT_ESCAPE_LOG_CODEPOINT_PACKET = 32
    D3DKMT_ESCAPE_LOG_USERMODE_DAIG_PACKET = 33
    D3DKMT_ESCAPE_GET_EXTERNAL_DIAGNOSTICS = 34
    D3DKMT_ESCAPE_GET_DISPLAY_CONFIGURATIONS = 36
    D3DKMT_ESCAPE_QUERY_IOMMU_STATUS = 37
    D3DKMT_ESCAPE_CCD_DATABASE = 38
    D3DKMT_ESCAPE_WIN32K_START = 1024
    D3DKMT_ESCAPE_WIN32K_HIP_DEVICE_INFO = 1024
    D3DKMT_ESCAPE_WIN32K_QUERY_CD_ROTATION_BLOCK = 1025
    D3DKMT_ESCAPE_WIN32K_DPI_INFO = 1026
    D3DKMT_ESCAPE_WIN32K_PRESENTER_VIEW_INFO = 1027
    D3DKMT_ESCAPE_WIN32K_SYSTEM_DPI = 1028
    D3DKMT_ESCAPE_WIN32K_BDD_FALLBACK = 1029
    D3DKMT_ESCAPE_WIN32K_DDA_TEST_CTL = 1030
    D3DKMT_ESCAPE_WIN32K_USER_DETECTED_BLACK_SCREEN = 1031
    D3DKMT_ESCAPE_WIN32K_HMD_ENUM = 1032
    D3DKMT_ESCAPE_WIN32K_HMD_CONTROL = 1033
    D3DKMT_ESCAPE_WIN32K_LPMDISPLAY_CONTROL = 1034
make_global(D3DKMT_ESCAPETYPE)

class D3DKMT_VIDMMESCAPETYPE(Enum):
    D3DKMT_VIDMMESCAPETYPE_SETFAULT = 0
    D3DKMT_VIDMMESCAPETYPE_RUN_COHERENCY_TEST = 1
    D3DKMT_VIDMMESCAPETYPE_RUN_UNMAP_TO_DUMMY_PAGE_TEST = 2
    D3DKMT_VIDMMESCAPETYPE_APERTURE_CORRUPTION_CHECK = 3
    D3DKMT_VIDMMESCAPETYPE_SUSPEND_CPU_ACCESS_TEST = 4
    D3DKMT_VIDMMESCAPETYPE_EVICT = 5
    D3DKMT_VIDMMESCAPETYPE_EVICT_BY_NT_HANDLE = 6
    D3DKMT_VIDMMESCAPETYPE_GET_VAD_INFO = 7
    D3DKMT_VIDMMESCAPETYPE_SET_BUDGET = 8
    D3DKMT_VIDMMESCAPETYPE_SUSPEND_PROCESS = 9
    D3DKMT_VIDMMESCAPETYPE_RESUME_PROCESS = 10
    D3DKMT_VIDMMESCAPETYPE_GET_BUDGET = 11
    D3DKMT_VIDMMESCAPETYPE_SET_TRIM_INTERVALS = 12
    D3DKMT_VIDMMESCAPETYPE_EVICT_BY_CRITERIA = 13
    D3DKMT_VIDMMESCAPETYPE_WAKE = 14
    D3DKMT_VIDMMESCAPETYPE_DEFRAG = 15
make_global(D3DKMT_VIDMMESCAPETYPE)

class DXGK_PTE_PAGE_SIZE(Enum):
    DXGK_PTE_PAGE_TABLE_PAGE_4KB = 0
    DXGK_PTE_PAGE_TABLE_PAGE_64KB = 1
make_global(DXGK_PTE_PAGE_SIZE)

class D3DKMT_VAD_ESCAPE_COMMAND(Enum):
    D3DKMT_VAD_ESCAPE_GETNUMVADS = 0
    D3DKMT_VAD_ESCAPE_GETVAD = 1
    D3DKMT_VAD_ESCAPE_GETVADRANGE = 2
    D3DKMT_VAD_ESCAPE_GET_PTE = 3
    D3DKMT_VAD_ESCAPE_GET_GPUMMU_CAPS = 4
    D3DKMT_VAD_ESCAPE_GET_SEGMENT_CAPS = 5
make_global(D3DKMT_VAD_ESCAPE_COMMAND)

class D3DKMT_DEFRAG_ESCAPE_OPERATION(Enum):
    D3DKMT_DEFRAG_ESCAPE_GET_FRAGMENTATION_STATS = 0
    D3DKMT_DEFRAG_ESCAPE_DEFRAG_UPWARD = 1
    D3DKMT_DEFRAG_ESCAPE_DEFRAG_DOWNWARD = 2
    D3DKMT_DEFRAG_ESCAPE_DEFRAG_PASS = 3
    D3DKMT_DEFRAG_ESCAPE_VERIFY_TRANSFER = 4
make_global(D3DKMT_DEFRAG_ESCAPE_OPERATION)

class D3DKMT_TDRDBGCTRLTYPE(Enum):
    D3DKMT_TDRDBGCTRLTYPE_FORCETDR = 0
    D3DKMT_TDRDBGCTRLTYPE_DISABLEBREAK = 1
    D3DKMT_TDRDBGCTRLTYPE_ENABLEBREAK = 2
    D3DKMT_TDRDBGCTRLTYPE_UNCONDITIONAL = 3
    D3DKMT_TDRDBGCTRLTYPE_VSYNCTDR = 4
    D3DKMT_TDRDBGCTRLTYPE_GPUTDR = 5
    D3DKMT_TDRDBGCTRLTYPE_FORCEDODTDR = 6
    D3DKMT_TDRDBGCTRLTYPE_FORCEDODVSYNCTDR = 7
    D3DKMT_TDRDBGCTRLTYPE_ENGINETDR = 8
make_global(D3DKMT_TDRDBGCTRLTYPE)

class D3DKMT_VIDSCHESCAPETYPE(Enum):
    D3DKMT_VIDSCHESCAPETYPE_PREEMPTIONCONTROL = 0
    D3DKMT_VIDSCHESCAPETYPE_SUSPENDSCHEDULER = 1
    D3DKMT_VIDSCHESCAPETYPE_TDRCONTROL = 2
    D3DKMT_VIDSCHESCAPETYPE_SUSPENDRESUME = 3
    D3DKMT_VIDSCHESCAPETYPE_ENABLECONTEXTDELAY = 4
    D3DKMT_VIDSCHESCAPETYPE_CONFIGURE_TDR_LIMIT = 5
    D3DKMT_VIDSCHESCAPETYPE_VGPU_RESET = 6
    D3DKMT_VIDSCHESCAPETYPE_PFN_CONTROL = 7
make_global(D3DKMT_VIDSCHESCAPETYPE)

class D3DKMT_ESCAPE_PFN_CONTROL_COMMAND(Enum):
    D3DKMT_ESCAPE_PFN_CONTROL_DEFAULT = 0
    D3DKMT_ESCAPE_PFN_CONTROL_FORCE_CPU = 1
    D3DKMT_ESCAPE_PFN_CONTROL_FORCE_GPU = 2
make_global(D3DKMT_ESCAPE_PFN_CONTROL_COMMAND)

class D3DKMT_DEVICEESCAPE_TYPE(Enum):
    D3DKMT_DEVICEESCAPE_VIDPNFROMALLOCATION = 0
    D3DKMT_DEVICEESCAPE_RESTOREGAMMA = 1
make_global(D3DKMT_DEVICEESCAPE_TYPE)

class D3DKMT_DMMESCAPETYPE(Enum):
    D3DKMT_DMMESCAPETYPE_UNINITIALIZED = 0
    D3DKMT_DMMESCAPETYPE_GET_SUMMARY_INFO = 1
    D3DKMT_DMMESCAPETYPE_GET_VIDEO_PRESENT_SOURCES_INFO = 2
    D3DKMT_DMMESCAPETYPE_GET_VIDEO_PRESENT_TARGETS_INFO = 3
    D3DKMT_DMMESCAPETYPE_GET_ACTIVEVIDPN_INFO = 4
    D3DKMT_DMMESCAPETYPE_GET_MONITORS_INFO = 5
    D3DKMT_DMMESCAPETYPE_RECENTLY_COMMITTED_VIDPNS_INFO = 6
    D3DKMT_DMMESCAPETYPE_RECENT_MODECHANGE_REQUESTS_INFO = 7
    D3DKMT_DMMESCAPETYPE_RECENTLY_RECOMMENDED_VIDPNS_INFO = 8
    D3DKMT_DMMESCAPETYPE_RECENT_MONITOR_PRESENCE_EVENTS_INFO = 9
    D3DKMT_DMMESCAPETYPE_ACTIVEVIDPN_SOURCEMODESET_INFO = 10
    D3DKMT_DMMESCAPETYPE_ACTIVEVIDPN_COFUNCPATHMODALITY_INFO = 11
    D3DKMT_DMMESCAPETYPE_GET_LASTCLIENTCOMMITTEDVIDPN_INFO = 12
    D3DKMT_DMMESCAPETYPE_GET_VERSION_INFO = 13
    D3DKMT_DMMESCAPETYPE_VIDPN_MGR_DIAGNOSTICS = 14
make_global(D3DKMT_DMMESCAPETYPE)

class D3DKMT_ACTIVATE_SPECIFIC_DIAG_TYPE(Enum):
    D3DKMT_ACTIVATE_SPECIFIC_DIAG_TYPE_EXTRA_CCD_DATABASE_INFO = 0
    D3DKMT_ACTIVATE_SPECIFIC_DIAG_TYPE_MODES_PRUNED = 15
make_global(D3DKMT_ACTIVATE_SPECIFIC_DIAG_TYPE)

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
make_global(WOW64_SHARED_INFORMATION)

class DOMAIN_INFORMATION_CLASS(Enum):
    DomainPasswordInformation = 1
    DomainGeneralInformation = 2
    DomainLogoffInformation = 3
    DomainOemInformation = 4
    DomainNameInformation = 5
    DomainReplicationInformation = 6
    DomainServerRoleInformation = 7
    DomainModifiedInformation = 8
    DomainStateInformation = 9
    DomainUasInformation = 10
    DomainGeneralInformation2 = 11
    DomainLockoutInformation = 12
    DomainModifiedInformation2 = 13
make_global(DOMAIN_INFORMATION_CLASS)

class DOMAIN_SERVER_ENABLE_STATE(Enum):
    DomainServerEnabled = 1
    DomainServerDisabled = 2
make_global(DOMAIN_SERVER_ENABLE_STATE)

class DOMAIN_SERVER_ROLE(Enum):
    DomainServerRoleBackup = 2
    DomainServerRolePrimary = 3
make_global(DOMAIN_SERVER_ROLE)

class DOMAIN_PASSWORD_CONSTRUCTION(Enum):
    DomainPasswordSimple = 1
    DomainPasswordComplex = 2
make_global(DOMAIN_PASSWORD_CONSTRUCTION)

class DOMAIN_DISPLAY_INFORMATION(Enum):
    DomainDisplayUser = 1
    DomainDisplayMachine = 2
    DomainDisplayGroup = 3
    DomainDisplayOemUser = 4
    DomainDisplayOemGroup = 5
    DomainDisplayServer = 6
make_global(DOMAIN_DISPLAY_INFORMATION)

class DOMAIN_LOCALIZABLE_ACCOUNTS_INFORMATION(Enum):
    DomainLocalizableAccountsBasic = 1
make_global(DOMAIN_LOCALIZABLE_ACCOUNTS_INFORMATION)

class GROUP_INFORMATION_CLASS(Enum):
    GroupGeneralInformation = 1
    GroupNameInformation = 2
    GroupAttributeInformation = 3
    GroupAdminCommentInformation = 4
    GroupReplicationInformation = 5
make_global(GROUP_INFORMATION_CLASS)

class ALIAS_INFORMATION_CLASS(Enum):
    AliasGeneralInformation = 1
    AliasNameInformation = 2
    AliasAdminCommentInformation = 3
    AliasReplicationInformation = 4
    AliasExtendedInformation = 5
make_global(ALIAS_INFORMATION_CLASS)

class USER_INFORMATION_CLASS(Enum):
    UserGeneralInformation = 1
    UserPreferencesInformation = 2
    UserLogonInformation = 3
    UserLogonHoursInformation = 4
    UserAccountInformation = 5
    UserNameInformation = 6
    UserAccountNameInformation = 7
    UserFullNameInformation = 8
    UserPrimaryGroupInformation = 9
    UserHomeInformation = 10
    UserScriptInformation = 11
    UserProfileInformation = 12
    UserAdminCommentInformation = 13
    UserWorkStationsInformation = 14
    UserSetPasswordInformation = 15
    UserControlInformation = 16
    UserExpiresInformation = 17
    UserInternal1Information = 18
    UserInternal2Information = 19
    UserParametersInformation = 20
    UserAllInformation = 21
    UserInternal3Information = 22
    UserInternal4Information = 23
    UserInternal5Information = 24
    UserInternal4InformationNew = 25
    UserInternal5InformationNew = 26
    UserInternal6Information = 27
    UserExtendedInformation = 28
    UserLogonUIInformation = 29
make_global(USER_INFORMATION_CLASS)

class SECURITY_DB_DELTA_TYPE(Enum):
    SecurityDbNew = 1
    SecurityDbRename = 2
    SecurityDbDelete = 3
    SecurityDbChangeMemberAdd = 4
    SecurityDbChangeMemberSet = 5
    SecurityDbChangeMemberDel = 6
    SecurityDbChange = 7
    SecurityDbChangePassword = 8
make_global(SECURITY_DB_DELTA_TYPE)

class SECURITY_DB_OBJECT_TYPE(Enum):
    SecurityDbObjectSamDomain = 1
    SecurityDbObjectSamUser = 2
    SecurityDbObjectSamGroup = 3
    SecurityDbObjectSamAlias = 4
    SecurityDbObjectLsaPolicy = 5
    SecurityDbObjectLsaTDomain = 6
    SecurityDbObjectLsaAccount = 7
    SecurityDbObjectLsaSecret = 8
make_global(SECURITY_DB_OBJECT_TYPE)

class SAM_ACCOUNT_TYPE(Enum):
    SamObjectUser = 1
    SamObjectGroup = 2
    SamObjectAlias = 3
make_global(SAM_ACCOUNT_TYPE)

class PASSWORD_POLICY_VALIDATION_TYPE(Enum):
    SamValidateAuthentication = 1
    SamValidatePasswordChange = 2
    SamValidatePasswordReset = 3
make_global(PASSWORD_POLICY_VALIDATION_TYPE)

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
make_global(SAM_VALIDATE_VALIDATION_STATUS)

class SAM_GENERIC_OPERATION_TYPE(Enum):
    SamObjectChangeNotificationOperation = 0
make_global(SAM_GENERIC_OPERATION_TYPE)

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
make_global(VDMSERVICECLASS)

class TRACE_CONTROL_INFORMATION_CLASS(Enum):
    TraceControlStartLogger = 1
    TraceControlStopLogger = 2
    TraceControlQueryLogger = 3
    TraceControlUpdateLogger = 4
    TraceControlFlushLogger = 5
    TraceControlIncrementLoggerFile = 6
    TraceControlRealtimeConnect = 11
    TraceControlWdiDispatchControl = 13
    TraceControlRealtimeDisconnectConsumerByHandle = 14
    TraceControlReceiveNotification = 16
    TraceControlEnableGuid = 17
    TraceControlSendReplyDataBlock = 18
    TraceControlReceiveReplyDataBlock = 19
    TraceControlWdiUpdateSem = 20
    TraceControlGetTraceGuidList = 21
    TraceControlGetTraceGuidInfo = 22
    TraceControlEnumerateTraceGuids = 23
    TraceControlQueryReferenceTime = 25
    TraceControlTrackProviderBinary = 26
    TraceControlAddNotificationEvent = 27
    TraceControlUpdateDisallowList = 28
    TraceControlUseDescriptorTypeUm = 31
    TraceControlGetTraceGroupList = 32
    TraceControlGetTraceGroupInfo = 33
    TraceControlTraceSetDisallowList = 34
    TraceControlSetCompressionSettings = 35
    TraceControlGetCompressionSettings = 36
    TraceControlUpdatePeriodicCaptureState = 37
    TraceControlGetPrivateSessionTraceHandle = 38
    TraceControlRegisterPrivateSession = 39
    TraceControlQuerySessionDemuxObject = 40
    TraceControlSetProviderBinaryTracking = 41
    TraceControlMaxLoggers = 42
    TraceControlMaxPmcCounter = 43
make_global(TRACE_CONTROL_INFORMATION_CLASS)

class AUDIT_EVENT_TYPE(Enum):
    AuditEventObjectAccess = 0
    AuditEventDirectoryServiceAccess = 1
make_global(AUDIT_EVENT_TYPE)

class TOKEN_TYPE(Enum):
    TokenPrimary = 1
    TokenImpersonation = 2
make_global(TOKEN_TYPE)

class KTMOBJECT_TYPE(Enum):
    KTMOBJECT_TRANSACTION = 0
    KTMOBJECT_TRANSACTION_MANAGER = 1
    KTMOBJECT_RESOURCE_MANAGER = 2
    KTMOBJECT_ENLISTMENT = 3
    KTMOBJECT_INVALID = 4
make_global(KTMOBJECT_TYPE)

class DEVICE_POWER_STATE(Enum):
    PowerDeviceUnspecified = 0
    PowerDeviceD0 = 1
    PowerDeviceD1 = 2
    PowerDeviceD2 = 3
    PowerDeviceD3 = 4
    PowerDeviceMaximum = 5
make_global(DEVICE_POWER_STATE)

class SYSTEM_POWER_STATE(Enum):
    PowerSystemUnspecified = 0
    PowerSystemWorking = 1
    PowerSystemSleeping1 = 2
    PowerSystemSleeping2 = 3
    PowerSystemSleeping3 = 4
    PowerSystemHibernate = 5
    PowerSystemShutdown = 6
    PowerSystemMaximum = 7
make_global(SYSTEM_POWER_STATE)

class ENLISTMENT_INFORMATION_CLASS(Enum):
    EnlistmentBasicInformation = 0
    EnlistmentRecoveryInformation = 1
    EnlistmentCrmInformation = 2
make_global(ENLISTMENT_INFORMATION_CLASS)

class JOBOBJECTINFOCLASS(Enum):
    JobObjectBasicAccountingInformation = 1
    JobObjectBasicLimitInformation = 2
    JobObjectBasicProcessIdList = 3
    JobObjectBasicUIRestrictions = 4
    JobObjectSecurityLimitInformation = 5
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
    MaxJobObjectInfoClass = 48
make_global(JOBOBJECTINFOCLASS)

class RESOURCEMANAGER_INFORMATION_CLASS(Enum):
    ResourceManagerBasicInformation = 0
    ResourceManagerCompletionInformation = 1
make_global(RESOURCEMANAGER_INFORMATION_CLASS)

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
    TokenOriginatingProcessTrustLevel = 48
    MaxTokenInfoClass = 49
make_global(TOKEN_INFORMATION_CLASS)

class TRANSACTION_INFORMATION_CLASS(Enum):
    TransactionBasicInformation = 0
    TransactionPropertiesInformation = 1
    TransactionEnlistmentInformation = 2
    TransactionSuperiorEnlistmentInformation = 3
    TransactionBindInformation = 4
    TransactionDTCPrivateInformation = 5
make_global(TRANSACTION_INFORMATION_CLASS)

class TRANSACTIONMANAGER_INFORMATION_CLASS(Enum):
    TransactionManagerBasicInformation = 0
    TransactionManagerLogInformation = 1
    TransactionManagerLogPathInformation = 2
    TransactionManagerRecoveryInformation = 4
    TransactionManagerOnlineProbeInformation = 3
    TransactionManagerOldestTransactionInformation = 5
make_global(TRANSACTIONMANAGER_INFORMATION_CLASS)

