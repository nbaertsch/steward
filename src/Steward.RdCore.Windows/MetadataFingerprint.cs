using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace Steward.RdCore.Windows;

internal sealed record ApiFingerprintResult(
    RdCoreCapabilityCode Code,
    IReadOnlyList<string> MissingMembers)
{
    public bool IsMatch => Code == RdCoreCapabilityCode.Compatible;
}

internal interface IRdCoreApiFingerprintInspector
{
    ApiFingerprintResult Inspect(string projectedAssemblyPath);
}

internal sealed class RdCoreApiFingerprintInspector :
    IRdCoreApiFingerprintInspector
{
    public const string FingerprintVersion = "rdcore-clientcore-v2";

    private static readonly RequiredMethod[] RequiredMethods =
    [
        Method("ActivityManager", ".ctor", "System.Void"),
        Method(
            "ActivityManager",
            "Initialize",
            "System.Void",
            "System.String",
            "System.String",
            "System.String",
            "System.String",
            "System.UInt16",
            "Microsoft.RemoteDesktop.ClientCore.LogLevel"),
        Method(
            "ActivityManager",
            "ConfigureClaimsTokenAuthenticationContext",
            "System.Void",
            "System.String",
            "System.String"),
        Method(
            "ActivityManager",
            "CreateConnection",
            "Microsoft.RemoteDesktop.ClientCore.IConnection",
            "System.String"),
        Method(
            "ActivityManager",
            "CreateWorkspaceDownloader",
            "Microsoft.RemoteDesktop.ClientCore.IWorkspaceDownloader"),
        Method(
            "ActivityManager",
            "GenerateNewActivityId",
            "System.Guid"),
        Method("IConnection", "Connect", "System.Void"),
        Method("IConnection", "Disconnect", "System.Void"),
        Method(
            "IConnection",
            "get_ConnectionSettings",
            "Microsoft.RemoteDesktop.ClientCore.IConnectionSettings"),
        Method(
            "IConnection",
            "set_ConnectionSettings",
            "System.Void",
            "Microsoft.RemoteDesktop.ClientCore.IConnectionSettings"),
        EventAdder(
            "Connected",
            "Microsoft.RemoteDesktop.ClientCore.IConnectedArgs"),
        EventRemover(
            "Connected",
            "Microsoft.RemoteDesktop.ClientCore.IConnectedArgs"),
        EventAdder(
            "Disconnected",
            "Microsoft.RemoteDesktop.ClientCore.IDisconnectedArgs"),
        EventRemover(
            "Disconnected",
            "Microsoft.RemoteDesktop.ClientCore.IDisconnectedArgs"),
        Method(
            "IDisconnectedArgs",
            "get_DisconnectCode",
            "Microsoft.RemoteDesktop.ClientCore.DisconnectionReasonCode"),
        Method(
            "IDisconnectedArgs",
            "get_ClientStackDisconnectCode",
            "System.UInt32"),
        Method(
            "IDisconnectedArgs",
            "get_ServerStackDisconnectCode",
            "System.UInt32"),
        Method(
            "IDisconnectedArgs",
            "get_ErrorCodeSymbolic",
            "System.String"),
        EventAdder(
            "ConnectionStatusChanged",
            "Microsoft.RemoteDesktop.ClientCore.IConnectionStatusChangedArgs"),
        EventRemover(
            "ConnectionStatusChanged",
            "Microsoft.RemoteDesktop.ClientCore.IConnectionStatusChangedArgs"),
        EventAdder(
            "ClaimsTokenRequested",
            "Microsoft.RemoteDesktop.ClientCore.IClaimsTokenRequestedArgs"),
        EventRemover(
            "ClaimsTokenRequested",
            "Microsoft.RemoteDesktop.ClientCore.IClaimsTokenRequestedArgs"),
        EventAdder(
            "WTSPluginsLoaded",
            "Microsoft.RemoteDesktop.ClientCore.IWTSPluginsLoadedArgs"),
        EventRemover(
            "WTSPluginsLoaded",
            "Microsoft.RemoteDesktop.ClientCore.IWTSPluginsLoadedArgs"),
        Getter("ConnectionMode", "Microsoft.RemoteDesktop.ClientCore.ConnectionMode"),
        Setter("ConnectionMode", "Microsoft.RemoteDesktop.ClientCore.ConnectionMode"),
        Getter("CloudPCSettingsUri", "System.String"),
        Setter("CloudPCSettingsUri", "System.String"),
        Getter("AllowThirdPartyPlugins", "System.Boolean"),
        Setter("AllowThirdPartyPlugins", "System.Boolean"),
        Getter("ConsumerHandlesClaimsTokenRequest", "System.Boolean"),
        Setter("ConsumerHandlesClaimsTokenRequest", "System.Boolean"),
        Getter("FirstPartyDVCPlugins", "System.String"),
        Setter("FirstPartyDVCPlugins", "System.String"),
        Getter("PopupUIParentWindowHandle", "System.UInt64"),
        Setter("PopupUIParentWindowHandle", "System.UInt64"),
        Getter("SessionWindowHandle", "System.UInt64"),
        Setter("SessionWindowHandle", "System.UInt64"),
        Getter("StartFullscreen", "System.Boolean"),
        Setter("StartFullscreen", "System.Boolean"),
        SettingsInterfaceGetter(
            "ConnectionMode",
            "Microsoft.RemoteDesktop.ClientCore.ConnectionMode"),
        SettingsInterfaceSetter(
            "ConnectionMode",
            "Microsoft.RemoteDesktop.ClientCore.ConnectionMode"),
        SettingsInterfaceGetter("CloudPCSettingsUri", "System.String"),
        SettingsInterfaceSetter("CloudPCSettingsUri", "System.String"),
        SettingsInterfaceGetter("AllowThirdPartyPlugins", "System.Boolean"),
        SettingsInterfaceSetter("AllowThirdPartyPlugins", "System.Boolean"),
        SettingsInterfaceGetter(
            "ConsumerHandlesClaimsTokenRequest",
            "System.Boolean"),
        SettingsInterfaceSetter(
            "ConsumerHandlesClaimsTokenRequest",
            "System.Boolean"),
        SettingsInterfaceGetter("PopupUIParentWindowHandle", "System.UInt64"),
        SettingsInterfaceSetter("PopupUIParentWindowHandle", "System.UInt64"),
        SettingsInterfaceGetter("StartFullscreen", "System.Boolean"),
        SettingsInterfaceSetter("StartFullscreen", "System.Boolean"),
        Method(
            "IWorkspaceDownloader",
            "DownloadAsync",
            "Windows.Foundation.IAsyncOperation`1<" +
            "Microsoft.RemoteDesktop.ClientCore.IFeedDownloadResult>"),
        Method(
            "IWorkspaceDownloader",
            "get_WorkspaceSettings",
            "Microsoft.RemoteDesktop.ClientCore.IWorkspaceSettings"),
        Method(
            "IWorkspaceDownloader",
            "set_WorkspaceSettings",
            "System.Void",
            "Microsoft.RemoteDesktop.ClientCore.IWorkspaceSettings"),
        WorkspaceEvent(
            "ResourceListAvailable",
            "IResourceListAvailableEventArgs",
            add: true),
        WorkspaceEvent(
            "ResourceListAvailable",
            "IResourceListAvailableEventArgs",
            add: false),
        WorkspaceEvent(
            "WorkspaceDownloadCompleted",
            "IWorkspaceDownloadCompletedEventArgs",
            add: true),
        WorkspaceEvent(
            "WorkspaceDownloadCompleted",
            "IWorkspaceDownloadCompletedEventArgs",
            add: false),
        WorkspaceEvent(
            "WorkspaceDownloadStatusChanged",
            "IWorkspaceDownloadStatusChangedArgs",
            add: true),
        WorkspaceEvent(
            "WorkspaceDownloadStatusChanged",
            "IWorkspaceDownloadStatusChangedArgs",
            add: false),
        Method(
            "IWorkspaceDownloadStatusChangedArgs",
            "get_CurrentStatus",
            "Microsoft.RemoteDesktop.ClientCore.WorkspaceDownloadStatus"),
        WorkspaceGetter("FeedUrl", "System.String"),
        WorkspaceSetter("FeedUrl", "System.String"),
        WorkspaceGetter("UserName", "System.String"),
        WorkspaceSetter("UserName", "System.String"),
        WorkspaceGetter("ParentWindowHandle", "System.UInt64"),
        WorkspaceSetter("ParentWindowHandle", "System.UInt64"),
        WorkspaceGetter("ForceRefresh", "System.Boolean"),
        WorkspaceSetter("ForceRefresh", "System.Boolean"),
        WorkspaceGetter("AllowInteractivePrompts", "System.Boolean"),
        WorkspaceSetter("AllowInteractivePrompts", "System.Boolean"),
        WorkspaceGetter(
            "ActivityId",
            "System.Nullable`1<System.Guid>"),
        WorkspaceSetter(
            "ActivityId",
            "System.Nullable`1<System.Guid>"),
        WorkspaceGetter(
            "IconFormats",
            "System.Collections.Generic.IList`1<" +
            "Microsoft.RemoteDesktop.ClientCore.IconFormat>"),
        WorkspaceSetter(
            "IconFormats",
            "System.Collections.Generic.IList`1<" +
            "Microsoft.RemoteDesktop.ClientCore.IconFormat>"),
        Method(
            "IResourceListAvailableEventArgs",
            "get_Descriptor",
            "Microsoft.RemoteDesktop.ClientCore.WorkspaceDescriptor"),
        Method(
            "IResourceListAvailableEventArgs",
            "get_Resources",
            "System.Collections.Generic.IEnumerable`1<" +
            "Microsoft.RemoteDesktop.ClientCore.IWorkspaceResource>"),
        Method(
            "IFeedDownloadResult",
            "get_Status",
            "Microsoft.RemoteDesktop.ClientCore.OperationStatus"),
        Method(
            "IWorkspaceResource",
            "get_Id",
            "System.String"),
        Method(
            "IWorkspaceResource",
            "get_AccessState",
            "Microsoft.RemoteDesktop.ClientCore.AccessState"),
        Method(
            "IWorkspaceResource",
            "get_RdpFile",
            "Microsoft.RemoteDesktop.ClientCore.RdpFile"),
        Method(
            "IClaimsTokenRequestedArgs",
            "GetDeferral",
            "Windows.Foundation.Deferral"),
        ClaimsGetter("AuthorityUri", "System.String"),
        ClaimsGetter("Claims", "System.String"),
        ClaimsGetter("ClientId", "System.String"),
        ClaimsGetter("RedirectUri", "System.String"),
        ClaimsGetter("ResourceUri", "System.String"),
        ClaimsGetter("Scope", "System.String"),
        ClaimsGetter("UserNameHint", "System.String"),
        ClaimsGetter(
            "Request",
            "Microsoft.RemoteDesktop.ClientCore.IClaimsTokenRequest"),
        Method(
            "IClaimsTokenRequest",
            "ProvideClaimsToken",
            "System.Void",
            "System.String",
            "System.String",
            "System.String",
            "System.Boolean",
            "System.String",
            "System.String",
            "System.String"),
        Method("IClaimsTokenRequest", "Cancel", "System.Void")
    ];

    private static readonly RequiredField[] RequiredFields =
    [
        new("WorkspaceDescriptor", "Id", "System.String"),
        new("RdpFile", "RdpFileContents", "System.String"),
        new("RdpFile", "Url", "System.String"),
        new(
            "ConnectionMode",
            "Silent",
            "Microsoft.RemoteDesktop.ClientCore.ConnectionMode"),
        new(
            "AccessState",
            "SilentlyConnectable",
            "Microsoft.RemoteDesktop.ClientCore.AccessState"),
        new(
            "LogLevel",
            "None",
            "Microsoft.RemoteDesktop.ClientCore.LogLevel"),
        new(
            "OperationStatus",
            "Success",
            "Microsoft.RemoteDesktop.ClientCore.OperationStatus"),
        new(
            "OperationStatus",
            "NoResourcesPublished",
            "Microsoft.RemoteDesktop.ClientCore.OperationStatus"),
        new(
            "IconFormat",
            "Png",
            "Microsoft.RemoteDesktop.ClientCore.IconFormat"),
        new(
            "IconFormat",
            "Ico",
            "Microsoft.RemoteDesktop.ClientCore.IconFormat")
    ];

    private readonly IRdCoreFileSystem fileSystem;

    public RdCoreApiFingerprintInspector(IRdCoreFileSystem fileSystem)
    {
        this.fileSystem = fileSystem;
    }

    public ApiFingerprintResult Inspect(string projectedAssemblyPath)
    {
        using var stream = fileSystem.OpenRead(projectedAssemblyPath);
        using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);
        if (!peReader.HasMetadata)
        {
            return new(
                RdCoreCapabilityCode.ManagedMetadataMissing,
                ["managed metadata"]);
        }

        var metadata = peReader.GetMetadataReader();
        var provider = new MetadataTypeNameProvider();
        var publicTypes = ReadPublicTypes(metadata);
        var missing = new List<string>();
        foreach (var required in RequiredMethods)
        {
            if (!publicTypes.TryGetValue(required.TypeName, out var type) ||
                !HasMethod(metadata, provider, type, required))
            {
                missing.Add($"{required.TypeName}.{required.MethodName}");
            }
        }

        foreach (var required in RequiredFields)
        {
            if (!publicTypes.TryGetValue(required.TypeName, out var type) ||
                !HasField(metadata, provider, type, required))
            {
                missing.Add($"{required.TypeName}.{required.FieldName}");
            }
        }

        return missing.Count == 0
            ? new(RdCoreCapabilityCode.Compatible, [])
            : new(RdCoreCapabilityCode.ApiFingerprintMismatch, missing);
    }

    private static Dictionary<string, TypeDefinition> ReadPublicTypes(
        MetadataReader metadata)
    {
        const string requiredNamespace = "Microsoft.RemoteDesktop.ClientCore";
        var types = new Dictionary<string, TypeDefinition>(StringComparer.Ordinal);
        foreach (var handle in metadata.TypeDefinitions)
        {
            var type = metadata.GetTypeDefinition(handle);
            if ((type.Attributes & TypeAttributes.VisibilityMask) !=
                TypeAttributes.Public ||
                !string.Equals(
                    metadata.GetString(type.Namespace),
                    requiredNamespace,
                    StringComparison.Ordinal))
            {
                continue;
            }

            types[metadata.GetString(type.Name)] = type;
        }

        return types;
    }

    private static bool HasMethod(
        MetadataReader metadata,
        MetadataTypeNameProvider provider,
        TypeDefinition type,
        RequiredMethod required)
    {
        foreach (var handle in type.GetMethods())
        {
            var method = metadata.GetMethodDefinition(handle);
            if ((method.Attributes & MethodAttributes.MemberAccessMask) !=
                MethodAttributes.Public ||
                !string.Equals(
                    metadata.GetString(method.Name),
                    required.MethodName,
                    StringComparison.Ordinal))
            {
                continue;
            }

            var signature = method.DecodeSignature(provider, genericContext: null);
            if (string.Equals(
                    signature.ReturnType,
                    required.ReturnType,
                    StringComparison.Ordinal) &&
                signature.ParameterTypes.SequenceEqual(
                    required.ParameterTypes,
                    StringComparer.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static RequiredMethod Getter(string propertyName, string propertyType) =>
        Method("ConnectionSettings", $"get_{propertyName}", propertyType);

    private static RequiredMethod Setter(string propertyName, string propertyType) =>
        Method(
            "ConnectionSettings",
            $"set_{propertyName}",
            "System.Void",
            propertyType);

    private static RequiredMethod EventAdder(
        string eventName,
        string argumentType) =>
        ConnectionEvent($"add_{eventName}", argumentType);

    private static RequiredMethod EventRemover(
        string eventName,
        string argumentType) =>
        ConnectionEvent($"remove_{eventName}", argumentType);

    private static RequiredMethod ConnectionEvent(
        string methodName,
        string argumentType) =>
        Method(
            "IConnection",
            methodName,
            "System.Void",
            "Windows.Foundation.TypedEventHandler`2<" +
            "Microsoft.RemoteDesktop.ClientCore.IConnection," +
            argumentType + ">");

    private static RequiredMethod WorkspaceGetter(
        string propertyName,
        string propertyType) =>
        Method("IWorkspaceSettings", $"get_{propertyName}", propertyType);

    private static RequiredMethod WorkspaceSetter(
        string propertyName,
        string propertyType) =>
        Method(
            "IWorkspaceSettings",
            $"set_{propertyName}",
            "System.Void",
            propertyType);

    private static RequiredMethod SettingsInterfaceGetter(
        string propertyName,
        string propertyType) =>
        Method("IConnectionSettings", $"get_{propertyName}", propertyType);

    private static RequiredMethod SettingsInterfaceSetter(
        string propertyName,
        string propertyType) =>
        Method(
            "IConnectionSettings",
            $"set_{propertyName}",
            "System.Void",
            propertyType);

    private static RequiredMethod WorkspaceEvent(
        string eventName,
        string argumentType,
        bool add) =>
        Method(
            "IWorkspaceDownloader",
            $"{(add ? "add" : "remove")}_{eventName}",
            "System.Void",
            "Windows.Foundation.TypedEventHandler`2<" +
            "Microsoft.RemoteDesktop.ClientCore.IWorkspaceDownloader," +
            "Microsoft.RemoteDesktop.ClientCore." + argumentType + ">");

    private static RequiredMethod ClaimsGetter(
        string propertyName,
        string propertyType) =>
        Method(
            "IClaimsTokenRequestedArgs",
            $"get_{propertyName}",
            propertyType);

    private static RequiredMethod Method(
        string typeName,
        string methodName,
        string returnType,
        params string[] parameterTypes) =>
        new(typeName, methodName, returnType, parameterTypes);

    private sealed record RequiredMethod(
        string TypeName,
        string MethodName,
        string ReturnType,
        IReadOnlyList<string> ParameterTypes);

    private static bool HasField(
        MetadataReader metadata,
        MetadataTypeNameProvider provider,
        TypeDefinition type,
        RequiredField required)
    {
        foreach (var handle in type.GetFields())
        {
            var field = metadata.GetFieldDefinition(handle);
            if ((field.Attributes & FieldAttributes.FieldAccessMask) ==
                    FieldAttributes.Public &&
                string.Equals(
                    metadata.GetString(field.Name),
                    required.FieldName,
                    StringComparison.Ordinal) &&
                string.Equals(
                    field.DecodeSignature(provider, genericContext: null),
                    required.FieldType,
                    StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private sealed record RequiredField(
        string TypeName,
        string FieldName,
        string FieldType);

    private sealed class MetadataTypeNameProvider :
        ISignatureTypeProvider<string, object?>
    {
        public string GetArrayType(string elementType, ArrayShape shape) =>
            elementType + "[]";

        public string GetByReferenceType(string elementType) => elementType + "&";

        public string GetFunctionPointerType(MethodSignature<string> signature) =>
            "function-pointer";

        public string GetGenericInstantiation(
            string genericType,
            ImmutableArray<string> typeArguments) =>
            genericType + "<" + string.Join(",", typeArguments) + ">";

        public string GetGenericMethodParameter(object? context, int index) =>
            "!!" + index;

        public string GetGenericTypeParameter(object? context, int index) =>
            "!" + index;

        public string GetModifiedType(
            string modifier,
            string unmodifiedType,
            bool isRequired) =>
            unmodifiedType;

        public string GetPinnedType(string elementType) => elementType;

        public string GetPointerType(string elementType) => elementType + "*";

        public string GetPrimitiveType(PrimitiveTypeCode typeCode) =>
            typeCode switch
            {
                PrimitiveTypeCode.Void => "System.Void",
                PrimitiveTypeCode.Boolean => "System.Boolean",
                PrimitiveTypeCode.Byte => "System.Byte",
                PrimitiveTypeCode.SByte => "System.SByte",
                PrimitiveTypeCode.Char => "System.Char",
                PrimitiveTypeCode.Int16 => "System.Int16",
                PrimitiveTypeCode.UInt16 => "System.UInt16",
                PrimitiveTypeCode.Int32 => "System.Int32",
                PrimitiveTypeCode.UInt32 => "System.UInt32",
                PrimitiveTypeCode.Int64 => "System.Int64",
                PrimitiveTypeCode.UInt64 => "System.UInt64",
                PrimitiveTypeCode.Single => "System.Single",
                PrimitiveTypeCode.Double => "System.Double",
                PrimitiveTypeCode.String => "System.String",
                PrimitiveTypeCode.IntPtr => "System.IntPtr",
                PrimitiveTypeCode.UIntPtr => "System.UIntPtr",
                PrimitiveTypeCode.Object => "System.Object",
                _ => typeCode.ToString()
            };

        public string GetSZArrayType(string elementType) => elementType + "[]";

        public string GetTypeFromDefinition(
            MetadataReader reader,
            TypeDefinitionHandle handle,
            byte rawTypeKind)
        {
            var type = reader.GetTypeDefinition(handle);
            return GetFullName(reader, type.Namespace, type.Name);
        }

        public string GetTypeFromReference(
            MetadataReader reader,
            TypeReferenceHandle handle,
            byte rawTypeKind)
        {
            var type = reader.GetTypeReference(handle);
            return GetFullName(reader, type.Namespace, type.Name);
        }

        public string GetTypeFromSpecification(
            MetadataReader reader,
            object? genericContext,
            TypeSpecificationHandle handle,
            byte rawTypeKind) =>
            reader.GetTypeSpecification(handle)
                .DecodeSignature(this, genericContext);

        private static string GetFullName(
            MetadataReader reader,
            StringHandle namespaceHandle,
            StringHandle nameHandle)
        {
            var typeNamespace = reader.GetString(namespaceHandle);
            var typeName = reader.GetString(nameHandle);
            return string.IsNullOrEmpty(typeNamespace)
                ? typeName
                : typeNamespace + "." + typeName;
        }
    }
}
