﻿// This file is used by Code Analysis to maintain SuppressMessage 
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given 
// a specific target and scoped to a namespace, type, member, etc.
//
// To add a suppression to this file, right-click the message in the 
// Code Analysis results, point to "Suppress Message", and click 
// "In Suppression File".
// You do not need to add suppressions to this file manually.

[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1721:PropertyNamesShouldNotMatchGetMethods", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding.#Type")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1721:PropertyNamesShouldNotMatchGetMethods", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.BindingMetadata.#Type")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptorProvider.#ParseQueueTrigger(Microsoft.Azure.WebJobs.Script.Description.QueueBindingMetadata,System.Type)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptorProvider.#ParseBlobTrigger(Microsoft.Azure.WebJobs.Script.Description.BlobBindingMetadata,System.Type)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptorProvider.#ParseServiceBusTrigger(Microsoft.Azure.WebJobs.Script.Description.ServiceBusBindingMetadata,System.Type)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptorProvider.#ParseTimerTrigger(Microsoft.Azure.WebJobs.Script.Description.TimerBindingMetadata,System.Type)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1011:ConsiderPassingBaseTypesAsParameters", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptorProvider.#ParseHttpTrigger(Microsoft.Azure.WebJobs.Script.Description.HttpBindingMetadata,System.Collections.ObjectModel.Collection`1<System.Reflection.Emit.CustomAttributeBuilder>,System.Type)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptorProvider.#ParseHttpTrigger(Microsoft.Azure.WebJobs.Script.Description.HttpBindingMetadata,System.Collections.ObjectModel.Collection`1<System.Reflection.Emit.CustomAttributeBuilder>,System.Type)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptorProvider.#ParseManualTrigger(Microsoft.Azure.WebJobs.Script.Description.BindingMetadata,System.Collections.ObjectModel.Collection`1<System.Reflection.Emit.CustomAttributeBuilder>,System.Type)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1804:RemoveUnusedLocals", MessageId = "argsLocal", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionGenerator.#Generate(System.String,System.String,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptor>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1804:RemoveUnusedLocals", MessageId = "invokerLocal", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionGenerator.#Generate(System.String,System.String,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptor>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1810:InitializeReferenceTypeStaticFieldsInline", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.NodeFunctionInvoker.#.cctor()")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA1801:ReviewUnusedParameters", MessageId = "binder", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.NodeFunctionInvoker.#CreateScriptExecutionContext(System.Object,Microsoft.Azure.WebJobs.Host.TraceWriter,Microsoft.Azure.WebJobs.Host.TraceWriter,Microsoft.Azure.WebJobs.IBinder,Microsoft.Azure.WebJobs.ExecutionContext)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1721:PropertyNamesShouldNotMatchGetMethods", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.ParameterDescriptor.#Type")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA1801:ReviewUnusedParameters", MessageId = "outputBindings", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.ScriptFunctionInvoker.#InitializeEnvironmentVariables(System.Collections.Generic.Dictionary`2<System.String,System.String>,System.String,System.Object,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,Microsoft.Azure.WebJobs.ExecutionContext)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA1801:ReviewUnusedParameters", MessageId = "cancellationToken", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.ScriptHostManager.#RunAndBlock(System.Threading.CancellationToken)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.ScriptHostManager.#RunAndBlock(System.Threading.CancellationToken)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1804:RemoveUnusedLocals", MessageId = "taskIgnore", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.ScriptHostManager.#RunAndBlock(System.Threading.CancellationToken)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.NodeFunctionInvoker.#.ctor(Microsoft.Azure.WebJobs.Script.ScriptHost,Microsoft.Azure.WebJobs.Script.Description.BindingMetadata,Microsoft.Azure.WebJobs.Script.Description.FunctionMetadata,System.Boolean,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.ScriptFunctionInvoker.#CreateProcess(System.String,System.String,System.String,System.Collections.Generic.IDictionary`2<System.String,System.String>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1062:Validate arguments of public methods", MessageId = "0", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.ScriptHost.#.ctor(Microsoft.Azure.WebJobs.Script.ScriptHostConfiguration)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.ScriptHost.#.ctor(Microsoft.Azure.WebJobs.Script.ScriptHostConfiguration)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.ScriptHost.#Create(Microsoft.Azure.WebJobs.Script.ScriptHostConfiguration)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptorProvider.#ParseEventHubTrigger(Microsoft.Azure.WebJobs.Script.Description.EventHubBindingMetadata,System.Type)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.CSharpFunctionInvoker.#.ctor(Microsoft.Azure.WebJobs.Script.ScriptHost,Microsoft.Azure.WebJobs.Script.Description.FunctionMetadata,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,Microsoft.Azure.WebJobs.Script.Description.IFunctionEntryPointResolver,Microsoft.Azure.WebJobs.Script.Description.FunctionAssemblyLoader)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.PackageManager.#RestorePackagesAsync()")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.CSharpFunctionInvoker.#ConvertBindingValue(System.Object)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1062:Validate arguments of public methods", MessageId = "1", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.CSharpFunctionInvoker.#OnScriptFileChanged(System.Object,System.IO.FileSystemEventArgs)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1062:Validate arguments of public methods", MessageId = "1", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.NodeFunctionInvoker.#OnScriptFileChanged(System.Object,System.IO.FileSystemEventArgs)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.ScriptFunctionInvokerBase.#InitializeFileWatcherIfEnabled()")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.CSharpFunctionDescriptionProvider.#CreateFunctionInvoker(System.String,Microsoft.Azure.WebJobs.Script.Description.BindingMetadata,Microsoft.Azure.WebJobs.Script.Description.FunctionMetadata,System.Boolean,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.NodeFunctionDescriptorProvider.#CreateFunctionInvoker(System.String,Microsoft.Azure.WebJobs.Script.Description.BindingMetadata,Microsoft.Azure.WebJobs.Script.Description.FunctionMetadata,System.Boolean,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.ScriptFunctionDescriptorProvider.#CreateFunctionInvoker(System.String,Microsoft.Azure.WebJobs.Script.Description.BindingMetadata,Microsoft.Azure.WebJobs.Script.Description.FunctionMetadata,System.Boolean,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2001:AvoidCallingProblematicMethods", MessageId = "System.Reflection.Assembly.LoadFile", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionMetadataResolver.#ResolveAssembly(System.String)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.HttpTriggerBindingMetadata.#Methods")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1011:ConsiderPassingBaseTypesAsParameters", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptorProvider.#ParseHttpTrigger(Microsoft.Azure.WebJobs.Script.Description.HttpTriggerBindingMetadata,System.Collections.ObjectModel.Collection`1<System.Reflection.Emit.CustomAttributeBuilder>,System.Type)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptorProvider.#ParseHttpTrigger(Microsoft.Azure.WebJobs.Script.Description.HttpTriggerBindingMetadata,System.Collections.ObjectModel.Collection`1<System.Reflection.Emit.CustomAttributeBuilder>,System.Type)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.CSharpFunctionDescriptionProvider.#CreateFunctionInvoker(System.String,Microsoft.Azure.WebJobs.Script.Description.BindingMetadata,Microsoft.Azure.WebJobs.Script.Description.FunctionMetadata,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.NodeFunctionDescriptorProvider.#CreateFunctionInvoker(System.String,Microsoft.Azure.WebJobs.Script.Description.BindingMetadata,Microsoft.Azure.WebJobs.Script.Description.FunctionMetadata,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.ScriptFunctionDescriptorProvider.#CreateFunctionInvoker(System.String,Microsoft.Azure.WebJobs.Script.Description.BindingMetadata,Microsoft.Azure.WebJobs.Script.Description.FunctionMetadata,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1502:AvoidExcessiveComplexity", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Binding.HttpBinding.#AddResponseHeader(System.Net.Http.HttpResponseMessage,System.Collections.Generic.KeyValuePair`2<System.String,Newtonsoft.Json.Linq.JToken>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.ScriptHostConfiguration.#Active")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.ScriptHostConfiguration.#Functions")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionValueLoader.#Create(System.Func`2<System.Threading.CancellationToken,System.Reflection.MethodInfo>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.FileTraceWriter.#.ctor(System.String,System.Diagnostics.TraceLevel)", Justification = "Disposed in IDisposable implementation.")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.ScriptFunctionInvokerBase.#CreateTraceWriter(Microsoft.Azure.WebJobs.Script.ScriptHostConfiguration,System.String)", Justification = "Disposed in IDisposable implementation.")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1502:AvoidExcessiveComplexity", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.ScriptHost.#ApplyConfiguration(Newtonsoft.Json.Linq.JObject,Microsoft.Azure.WebJobs.Script.ScriptHostConfiguration)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.ScriptHost.#Initialize()")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA1801:ReviewUnusedParameters", MessageId = "metadata", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding.#.ctor(Microsoft.Azure.WebJobs.Script.ScriptHostConfiguration,Microsoft.Azure.WebJobs.Script.Description.BindingMetadata,System.IO.FileAccess)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1011:ConsiderPassingBaseTypesAsParameters", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptorProvider.#ParseHttpTrigger(Microsoft.Azure.WebJobs.Script.Description.HttpTriggerBindingMetadata,System.Type)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptorProvider.#ParseHttpTrigger(Microsoft.Azure.WebJobs.Script.Description.HttpTriggerBindingMetadata,System.Type)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptorProvider.#ParseManualTrigger(Microsoft.Azure.WebJobs.Script.Description.BindingMetadata,System.Type)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1056:UriPropertiesShouldNotBeStrings", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Binding.MobileTableBinding.#MobileAppUri")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1702:CompoundWordsShouldBeCasedCorrectly", MessageId = "Javascript", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.ScriptType.#Javascript")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "PHP", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.ScriptType.#PHP")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Powershell", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.ScriptType.#Powershell")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1004:GenericMethodsShouldProvideTypeParameter", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding.#BindAsyncCollectorAsync`1(System.IO.Stream,Microsoft.Azure.WebJobs.Host.Bindings.Runtime.IBinderEx,Microsoft.Azure.WebJobs.Host.Bindings.Runtime.RuntimeBindingContext)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionDescriptorProvider.#ParseApiHubFileTrigger(Microsoft.Azure.WebJobs.Script.Description.ApiHubBindingMetadata,System.Type)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionInvokerBase.#CreateTraceWriter(Microsoft.Azure.WebJobs.Script.ScriptHostConfiguration,System.String)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionInvokerBase.#InitializeFileWatcherIfEnabled()")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Binding.HttpBinding.#ProcessResult(System.Collections.Generic.IDictionary`2<System.String,System.Object>,System.Object[],System.String,System.Object)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2001:AvoidCallingProblematicMethods", MessageId = "System.Reflection.Assembly.LoadFrom", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.LocalSharedAssemblyProvider.#TryResolveAssembly(System.String,System.Reflection.Assembly&)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.DotNetFunctionDescriptionProvider.#CreateFunctionInvoker(System.String,Microsoft.Azure.WebJobs.Script.Description.BindingMetadata,Microsoft.Azure.WebJobs.Script.Description.FunctionMetadata,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.PowerShellFunctionDescriptionProvider.#CreateFunctionInvoker(System.String,Microsoft.Azure.WebJobs.Script.Description.BindingMetadata,Microsoft.Azure.WebJobs.Script.Description.FunctionMetadata,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.PowerShellFunctionInvoker.#InvokePowerShellScript()")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.PowerShellFunctionInvoker.#InvokePowerShellScript()")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Binding.HttpBinding.#BindAsync(Microsoft.Azure.WebJobs.Script.Binding.BindingContext)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1045:DoNotPassTypesByReference", MessageId = "2#", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding.#ConvertStreamToValue(System.IO.Stream,Microsoft.Azure.WebJobs.Script.Description.DataType,System.Object&)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1007:UseGenericsWhereAppropriate", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding.#ConvertStreamToValue(System.IO.Stream,Microsoft.Azure.WebJobs.Script.Description.DataType,System.Object&)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.PowerShellFunctionDescriptorProvider.#CreateFunctionInvoker(System.String,Microsoft.Azure.WebJobs.Script.Description.BindingMetadata,Microsoft.Azure.WebJobs.Script.Description.FunctionMetadata,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2001:AvoidCallingProblematicMethods", MessageId = "System.Reflection.Assembly.LoadFrom", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionMetadataResolver.#ResolveAssembly(System.String)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.ScriptFunctionInvokerBase.#InitializeEnvironmentVariables(System.Collections.Generic.Dictionary`2<System.String,System.String>,System.String,System.Object,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,Microsoft.Azure.WebJobs.ExecutionContext)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.ScriptFunctionInvokerBase.#ProcessInputBindingsAsync(System.Object,System.String,Microsoft.Azure.WebJobs.Host.Bindings.Runtime.IBinderEx,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,System.Collections.Generic.Dictionary`2<System.String,System.String>,System.Collections.Generic.Dictionary`2<System.String,System.String>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.DotNetFunctionDescriptorProvider.#CreateFunctionInvoker(System.String,Microsoft.Azure.WebJobs.Script.Description.BindingMetadata,Microsoft.Azure.WebJobs.Script.Description.FunctionMetadata,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.BindingMetadata.#Raw")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1819:PropertiesShouldNotReturnArrays", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Binding.BindingContext.#Attributes")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "refkind", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.FunctionParameter.#.ctor(System.String,System.String,System.Boolean,Microsoft.CodeAnalysis.RefKind)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.BlobLeaseManager.#Create(System.String,System.TimeSpan,System.String,Microsoft.Azure.WebJobs.Host.TraceWriter)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.BlobLeaseManager.#Create(System.String,System.TimeSpan,System.String,System.String,Microsoft.Azure.WebJobs.Host.TraceWriter)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Binding.Http.HttpTriggerAttributeBindingProvider+HttpTriggerBinding.#CreateListenerAsync(Microsoft.Azure.WebJobs.Host.Listeners.ListenerFactoryContext)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Binding.Http.HttpTriggerAttributeBindingProvider+HttpTriggerBinding.#ToParameterDescriptor()")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Binding.Http.HttpTriggerAttributeBindingProvider+HttpTriggerBinding.#FromInvokeString(System.String)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1502:AvoidExcessiveComplexity", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.Description.DotNetFunctionDescriptorProvider.#GetFunctionParameters(Microsoft.Azure.WebJobs.Script.Description.IFunctionInvoker,Microsoft.Azure.WebJobs.Script.Description.FunctionMetadata,Microsoft.Azure.WebJobs.Script.Description.BindingMetadata,System.Collections.ObjectModel.Collection`1<System.Reflection.Emit.CustomAttributeBuilder>,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>,System.Collections.ObjectModel.Collection`1<Microsoft.Azure.WebJobs.Script.Binding.FunctionBinding>)")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.FunctionTraceWriterFactory.#Create()")]
[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Scope = "member", Target = "Microsoft.Azure.WebJobs.Script.ScriptHostConfiguration.#WatchDirectories")]

