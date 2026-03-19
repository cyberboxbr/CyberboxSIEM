type JsonRecord = Record<string, unknown>;

export interface EventContext {
  eventId?: string;
  source?: string;
  time?: string;
  eventCode?: string;
  eventName?: string;
  host?: string;
  user?: string;
  process?: string;
  processPath?: string;
  parentProcess?: string;
  commandLine?: string;
  sourceIp?: string;
  sourcePort?: string;
  destinationIp?: string;
  destinationPort?: string;
  destinationHost?: string;
  dnsQuery?: string;
  url?: string;
  filePath?: string;
  registryPath?: string;
  service?: string;
  hashes?: string;
  message?: string;
  summary: string;
  rawPayload: JsonRecord;
}

export interface EventContextAggregate {
  eventKinds: string[];
  sources: string[];
  hosts: string[];
  users: string[];
  processes: string[];
  sourceIps: string[];
  destinationIps: string[];
  networkFlows: string[];
  domains: string[];
  files: string[];
  registryPaths: string[];
  services: string[];
  messages: string[];
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function getPathValue(record: JsonRecord, path: string): unknown {
  const segments = path.split('.');
  let current: unknown = record;
  for (const segment of segments) {
    if (!isRecord(current) || !(segment in current)) {
      return undefined;
    }
    current = current[segment];
  }
  return current;
}

function normalizeText(text: string): string | undefined {
  const trimmed = text.trim();
  if (!trimmed) return undefined;
  const lowered = trimmed.toLowerCase();
  if (lowered === 'unknown' || lowered === 'n/a' || lowered === 'null' || lowered === 'undefined' || lowered === '--') {
    return undefined;
  }
  return trimmed;
}

function toText(value: unknown): string | undefined {
  if (typeof value === 'string') {
    return normalizeText(value);
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (Array.isArray(value)) {
    const values = value.map(toText).filter(Boolean) as string[];
    if (values.length === 0) return undefined;
    return values.join(', ');
  }
  if (isRecord(value)) {
    const nested = toText(value.message) ?? toText(value.msg) ?? toText(value.name) ?? toText(value.text);
    if (nested) {
      return nested;
    }
    try {
      const json = JSON.stringify(value);
      if (json && json.length <= 180) {
        return json;
      }
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function pickText(records: JsonRecord[], paths: string[]): string | undefined {
  for (const path of paths) {
    for (const record of records) {
      const value = toText(getPathValue(record, path));
      if (value) {
        return value;
      }
    }
  }
  return undefined;
}

function basenameish(value?: string): string | undefined {
  if (!value) return undefined;
  const parts = value.split(/[\\/]/).filter(Boolean);
  return normalizeText(parts[parts.length - 1] ?? value) ?? normalizeText(value);
}

function truncate(text: string, max = 160): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max - 3)}...`;
}

function pushUnique(target: string[], value?: string, max = 6): void {
  if (!value || target.includes(value) || target.length >= max) return;
  target.push(value);
}

function eventKind(context: Pick<EventContext, 'eventName' | 'eventCode'>): string | undefined {
  if (context.eventName) return context.eventName;
  if (context.eventCode) return `Event ${context.eventCode}`;
  return undefined;
}

export function formatNetworkFlow(
  context: Pick<EventContext, 'sourceIp' | 'destinationIp' | 'destinationHost' | 'destinationPort'>,
): string | undefined {
  const destination = context.destinationIp ?? context.destinationHost;
  const port = context.destinationPort ? `:${context.destinationPort}` : '';
  if (context.sourceIp && destination) {
    return `${context.sourceIp} -> ${destination}${port}`;
  }
  if (destination) {
    return `${destination}${port}`;
  }
  return context.sourceIp;
}

export function limitValues(values: string[], max = 4): string[] {
  return values.slice(0, max);
}

export function extractEventContext(row: JsonRecord): EventContext {
  const rawPayload = isRecord(row.raw_payload) ? row.raw_payload : {};
  const topFirst = [row, rawPayload];
  const payloadFirst = [rawPayload, row];

  const eventId = pickText(topFirst, ['event_id', 'EventId', 'id']);
  const eventCode = pickText(payloadFirst, ['EventID', 'event_code', 'event_id', 'EventCode']);
  const eventName = pickText(topFirst, ['event_type', 'event_name', 'EventType', 'type', 'operation', 'Operation', 'channel', 'Channel']);
  const source = pickText(topFirst, ['source', 'source_name', 'log_source']);
  const time = pickText(topFirst, ['event_time', '_time', 'timestamp', '@timestamp', 'ingest_time', 'TimeCreated', 'UtcTime']);
  const host = pickText(topFirst, ['hostname', 'Computer', 'host.name', 'host', 'device_name', 'agent.hostname']);
  const user = pickText(topFirst, ['TargetUserName', 'SubjectUserName', 'User', 'user', 'username', 'account_name', 'user_name', 'principal']);
  const processPath = pickText(topFirst, ['Image', 'image', 'process.executable', 'process_path', 'process.path', 'ExecutablePath', 'exe', 'ProcessName']);
  const process = basenameish(processPath) ?? pickText(topFirst, ['process_name', 'process.name', 'ProcessName', 'process']);
  const parentProcess = basenameish(pickText(topFirst, ['ParentImage', 'parent_image', 'parent_process', 'ParentProcessName']));
  const commandLine = pickText(topFirst, ['CommandLine', 'command_line', 'cmdline', 'process.command_line', 'ProcessCommandLine']);
  const sourceIp = pickText(topFirst, ['SourceIp', 'source_ip', 'src_ip', 'source.address', 'client_ip', 'IpAddress', 'srcaddr', 'src']);
  const sourcePort = pickText(topFirst, ['SourcePort', 'source_port', 'src_port', 'client_port', 'srcport']);
  const destinationIp = pickText(topFirst, ['DestinationIp', 'destination_ip', 'dst_ip', 'destination.address', 'dest_ip', 'remote_ip', 'daddr', 'dstaddr']);
  const destinationPort = pickText(topFirst, ['DestinationPort', 'destination_port', 'dst_port', 'dest_port', 'remote_port', 'dport']);
  const destinationHost = pickText(topFirst, ['DestinationHostname', 'destination_hostname', 'dest_hostname', 'remote_host']);
  const dnsQuery = pickText(topFirst, ['QueryName', 'dns_query', 'query_name', 'query', 'DomainName', 'domain', 'domain_name']);
  const url = pickText(topFirst, ['url', 'uri', 'request_url', 'request_uri', 'full_url']);
  const filePath = pickText(topFirst, ['TargetFilename', 'file_path', 'FileName', 'path', 'ImageLoaded', 'SourceFilename']);
  const registryPath = pickText(topFirst, ['TargetObject', 'registry_path', 'registry_key']);
  const service = pickText(topFirst, ['ServiceName', 'service_name', 'Unit', 'unit', 'container_name']);
  const hashes = pickText(topFirst, ['Hashes', 'hashes', 'sha256', 'sha1', 'md5', 'hash']);
  const message = pickText(topFirst, ['message', 'Message', 'msg', 'short_message', 'rendered_message', 'description', 'summary']);
  const flow = formatNetworkFlow({ sourceIp, destinationIp, destinationHost, destinationPort });
  const artifact = filePath ?? registryPath ?? hashes;
  const summary = truncate(
    (eventName && process && `${eventName}: ${process}`)
      || (dnsQuery && `${eventName ?? 'DNS query'} ${dnsQuery}`)
      || (flow && `${eventName ?? 'Network activity'} ${flow}`)
      || (artifact && `${eventName ?? 'Artifact'} ${basenameish(artifact) ?? artifact}`)
      || message
      || eventKind({ eventName, eventCode })
      || source
      || 'Evidence event',
    140,
  );

  return {
    eventId,
    source,
    time,
    eventCode,
    eventName,
    host,
    user,
    process,
    processPath,
    parentProcess,
    commandLine,
    sourceIp,
    sourcePort,
    destinationIp,
    destinationPort,
    destinationHost,
    dnsQuery,
    url,
    filePath,
    registryPath,
    service,
    hashes,
    message,
    summary,
    rawPayload,
  };
}

export function aggregateEventContexts(contexts: EventContext[]): EventContextAggregate {
  const aggregate: EventContextAggregate = {
    eventKinds: [],
    sources: [],
    hosts: [],
    users: [],
    processes: [],
    sourceIps: [],
    destinationIps: [],
    networkFlows: [],
    domains: [],
    files: [],
    registryPaths: [],
    services: [],
    messages: [],
  };

  contexts.forEach((context) => {
    pushUnique(aggregate.eventKinds, eventKind(context));
    pushUnique(aggregate.sources, context.source);
    pushUnique(aggregate.hosts, context.host);
    pushUnique(aggregate.users, context.user);
    pushUnique(aggregate.processes, context.process ?? context.processPath);
    pushUnique(aggregate.sourceIps, context.sourceIp);
    pushUnique(aggregate.destinationIps, context.destinationIp ?? context.destinationHost);
    pushUnique(aggregate.networkFlows, formatNetworkFlow(context));
    pushUnique(aggregate.domains, context.dnsQuery ?? context.url);
    pushUnique(aggregate.files, context.filePath);
    pushUnique(aggregate.registryPaths, context.registryPath);
    pushUnique(aggregate.services, context.service);
    pushUnique(aggregate.messages, context.message && truncate(context.message, 120));
  });

  return aggregate;
}
