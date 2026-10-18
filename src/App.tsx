import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ChangeEvent, FormEvent } from 'react';
import {
  Activity,
  AlertCircle,
  ArrowRight,
  BarChart3,
  Boxes,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  ClipboardList,
  CloudOff,
  Database,
  Download,
  FileArchive,
  FileSearch,
  Filter,
  FolderKanban,
  GitBranch,
  Hash,
  History,
  Landmark,
  LoaderCircle,
  Menu,
  Network,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  Sparkles,
  TerminalSquare,
  Trash2,
  Upload,
  X,
} from 'lucide-react';
import {
  API_BASE_URL,
  api,
  formatApiError,
} from './api';
import type {
  AssetInput,
  AssetAssessmentResult,
  AssetRecord,
  CaseInput,
  CaseRecord,
  ConditionNode,
  EventRecord,
  GraphResult,
  HashResult,
  HealthResponse,
  IntelligenceResult,
  IocResult,
  LogResult,
  RuleRecord,
  RuleTestResult,
  VulnerabilitySearchResult,
} from './api';

type View =
  | 'command'
  | 'intelligence'
  | 'forensics'
  | 'timeline'
  | 'vulnerabilities'
  | 'rules'
  | 'assets'
  | 'cases'
  | 'reports'
  | 'graph'
  | 'settings';

type NoticeTone = 'success' | 'error' | 'info';
type Notify = (tone: NoticeTone, message: string) => void;
type ImportFormat = 'json' | 'csv';

interface NoticeState {
  tone: NoticeTone;
  message: string;
}

interface NavItem {
  id: View;
  label: string;
  hint: string;
  icon: typeof Activity;
}

const navigationItems: NavItem[] = [
  { id: 'command', label: 'Threat Command', hint: 'Operational overview', icon: Shield },
  { id: 'intelligence', label: 'Intelligence Lab', hint: 'Indicator investigations', icon: Search },
  { id: 'forensics', label: 'Digital Forensics', hint: 'Local evidence analysis', icon: FileSearch },
  { id: 'timeline', label: 'Event Timeline', hint: 'Persisted event stream', icon: History },
  { id: 'vulnerabilities', label: 'Vulnerability Research', hint: 'NVD search', icon: ShieldAlert },
  { id: 'rules', label: 'Detection Rules', hint: 'Test against events', icon: TerminalSquare },
  { id: 'assets', label: 'Asset Inventory', hint: 'Systems and identities', icon: Boxes },
  { id: 'cases', label: 'Cases', hint: 'Investigation records', icon: FolderKanban },
  { id: 'reports', label: 'Reports', hint: 'Evidence exports', icon: BarChart3 },
  { id: 'graph', label: 'Attack Graph', hint: 'Persisted relationships', icon: Network },
  { id: 'settings', label: 'Settings', hint: 'Backend status', icon: Settings },
];

const viewLabels: Record<View, string> = {
  command: 'Threat Command',
  intelligence: 'Intelligence Lab',
  forensics: 'Digital Forensics',
  timeline: 'Event Timeline',
  vulnerabilities: 'Vulnerability Research',
  rules: 'Detection Rules',
  assets: 'Asset Inventory',
  cases: 'Cases',
  reports: 'Reports',
  graph: 'Attack Graph',
  settings: 'Settings',
};

const SAMPLE_EVENTS: Record<ImportFormat, string> = {
  json: JSON.stringify([
    {
      timestamp: '2026-01-01T00:00:00Z',
      source: 'sample-host',
      event_type: 'authentication_failure',
      severity: 'medium',
      status: 'failed',
      detail: 'Sample import record — replace with your own telemetry.',
    },
  ], null, 2),
  csv: 'timestamp,source,event_type,severity,status,detail\n2026-01-01T00:00:00Z,sample-host,authentication_failure,medium,failed,"Sample import record — replace with your own telemetry."',
};

const SAMPLE_ASSETS: Record<ImportFormat, string> = {
  json: JSON.stringify([
    {
      name: 'sample-host',
      hostname: 'sample-host.local',
      ip: '192.0.2.10',
      kind: 'server',
      risk: 'unknown',
      status: 'observed',
    },
  ], null, 2),
  csv: 'name,hostname,ip,kind,risk,status\nsample-host,sample-host.local,192.0.2.10,server,unknown,observed',
};

function formatDate(value?: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function textValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function statusClass(value?: string | null): string {
  const normalized = (value || '').toLowerCase();
  if (['high', 'critical', 'malicious', 'suspicious', 'failed', 'error', 'unavailable'].some((item) => normalized.includes(item))) return 'danger';
  if (['medium', 'pending', 'unknown', 'blocked', 'no_result'].some((item) => normalized.includes(item))) return 'warning';
  if (['low', 'ok', 'result', 'open', 'active', 'public'].some((item) => normalized.includes(item))) return 'success';
  return 'neutral';
}

function describeCondition(condition?: ConditionNode): string {
  if (!condition) return 'No condition recorded';
  if (condition.op && condition.conditions) {
    return condition.conditions.map(describeCondition).join(` ${condition.op.toUpperCase()} `);
  }
  return `${condition.field || 'field'} ${condition.operator || 'matches'} ${textValue(condition.value)}`;
}

function Notice({ notice, onDismiss }: { notice: NoticeState | null; onDismiss: () => void }) {
  if (!notice) return null;
  const Icon = notice.tone === 'error' ? AlertCircle : notice.tone === 'success' ? Check : Activity;
  return (
    <div className={`blacksite-notice ${notice.tone}`} role={notice.tone === 'error' ? 'alert' : 'status'}>
      <Icon size={16} />
      <span>{notice.message}</span>
      <button className="icon-button" onClick={onDismiss} aria-label="Dismiss notification"><X size={15} /></button>
    </div>
  );
}

function LoadingState({ label = 'Loading backend records…' }: { label?: string }) {
  return <div className="blacksite-loading"><LoaderCircle size={20} className="spin" /><span>{label}</span></div>;
}

function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="empty-state blacksite-error-state">
      <div className="empty-icon"><CloudOff size={22} /></div>
      <h2>Backend data unavailable</h2>
      <p>{message}</p>
      {onRetry && <button className="button secondary-button" onClick={onRetry}><RefreshCw size={15} /> Retry</button>}
    </div>
  );
}

function EmptyState({ title, description, icon: Icon = Database, action }: { title: string; description: string; icon?: typeof Database; action?: React.ReactNode }) {
  return (
    <div className="empty-state">
      <div className="empty-icon"><Icon size={22} /></div>
      <h2>{title}</h2>
      <p>{description}</p>
      {action}
    </div>
  );
}

function App() {
  const [activeView, setActiveView] = useState<View>('command');
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [notice, setNotice] = useState<NoticeState | null>(null);

  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState(false);
  const [healthError, setHealthError] = useState<string | null>(null);

  const [events, setEvents] = useState<EventRecord[]>([]);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsError, setEventsError] = useState<string | null>(null);

  const [assets, setAssets] = useState<AssetRecord[]>([]);
  const [assetsLoading, setAssetsLoading] = useState(false);
  const [assetsError, setAssetsError] = useState<string | null>(null);

  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [casesLoading, setCasesLoading] = useState(false);
  const [casesError, setCasesError] = useState<string | null>(null);

  const [rules, setRules] = useState<RuleRecord[]>([]);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [rulesError, setRulesError] = useState<string | null>(null);

  const [graph, setGraph] = useState<GraphResult | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphError, setGraphError] = useState<string | null>(null);

  const [vulnerabilitySearch, setVulnerabilitySearch] = useState<VulnerabilitySearchResult | null>(null);
  const [vulnerabilitiesLoading, setVulnerabilitiesLoading] = useState(false);
  const [vulnerabilitiesError, setVulnerabilitiesError] = useState<string | null>(null);

  const notify = useCallback<Notify>((tone, message) => {
    setNotice({ tone, message });
  }, []);

  const loadHealth = useCallback(async () => {
    setHealthLoading(true);
    setHealthError(null);
    try {
      setHealth(await api.health());
    } catch (error) {
      setHealth(null);
      setHealthError(formatApiError(error));
    } finally {
      setHealthLoading(false);
    }
  }, []);

  const loadEvents = useCallback(async () => {
    setEventsLoading(true);
    setEventsError(null);
    try {
      const result = await api.events.list({ limit: 500 });
      setEvents(result.items);
      setEventsTotal(result.total);
    } catch (error) {
      setEventsError(formatApiError(error));
    } finally {
      setEventsLoading(false);
    }
  }, []);

  const loadAssets = useCallback(async () => {
    setAssetsLoading(true);
    setAssetsError(null);
    try {
      setAssets((await api.assets.list()).items);
    } catch (error) {
      setAssetsError(formatApiError(error));
    } finally {
      setAssetsLoading(false);
    }
  }, []);

  const loadCases = useCallback(async () => {
    setCasesLoading(true);
    setCasesError(null);
    try {
      setCases((await api.cases.list()).items);
    } catch (error) {
      setCasesError(formatApiError(error));
    } finally {
      setCasesLoading(false);
    }
  }, []);

  const loadRules = useCallback(async () => {
    setRulesLoading(true);
    setRulesError(null);
    try {
      setRules((await api.rules.list()).items);
    } catch (error) {
      setRulesError(formatApiError(error));
    } finally {
      setRulesLoading(false);
    }
  }, []);

  const loadGraph = useCallback(async () => {
    setGraphLoading(true);
    setGraphError(null);
    try {
      setGraph(await api.graph());
    } catch (error) {
      setGraphError(formatApiError(error));
    } finally {
      setGraphLoading(false);
    }
  }, []);

  const loadVulnerabilities = useCallback(async (query = '', filters: { severity?: string; published_after?: string; published_before?: string } = {}) => {
    setVulnerabilitiesLoading(true);
    setVulnerabilitiesError(null);
    try {
      setVulnerabilitySearch(await api.vulnerabilities.search(query, 20, filters));
    } catch (error) {
      setVulnerabilitySearch(null);
      setVulnerabilitiesError(formatApiError(error));
    } finally {
      setVulnerabilitiesLoading(false);
    }
  }, []);

  const loadCommandData = useCallback(async () => {
    await Promise.all([loadEvents(), loadAssets(), loadCases(), loadGraph(), loadVulnerabilities()]);
  }, [loadAssets, loadCases, loadEvents, loadGraph, loadVulnerabilities]);

  useEffect(() => {
    void loadHealth();
  }, [loadHealth]);

  useEffect(() => {
    if (activeView === 'command') void loadCommandData();
    if (activeView === 'timeline') void loadEvents();
    if (activeView === 'rules') {
      void loadRules();
      void loadEvents();
    }
    if (activeView === 'assets') void loadAssets();
    if (activeView === 'cases') {
      void loadCases();
      void loadAssets();
      void loadEvents();
    }
    if (activeView === 'reports') void loadCases();
    if (activeView === 'graph') void loadGraph();
  }, [activeView, loadAssets, loadCases, loadCommandData, loadEvents, loadGraph, loadRules]);

  const changeView = (view: View) => {
    setActiveView(view);
    setMobileNavOpen(false);
  };

  const importEvents = async (content: string, format: ImportFormat): Promise<number> => {
    const result = await api.events.import(content, format);
    await loadEvents();
    notify('success', `Imported ${result.imported} event${result.imported === 1 ? '' : 's'} into the backend.`);
    return result.imported;
  };

  const importAssets = async (content: string, format: ImportFormat): Promise<number> => {
    const result = await api.assets.import(content, format);
    await loadAssets();
    notify('success', `Imported ${result.imported} asset${result.imported === 1 ? '' : 's'} into the backend.`);
    return result.imported;
  };

  const saveAsset = async (id: number | null, body: AssetInput) => {
    try {
      if (id) await api.assets.update(id, body);
      else await api.assets.create(body);
      await loadAssets();
      notify('success', id ? 'Asset updated in the backend.' : 'Asset created in the backend.');
    } catch (error) {
      notify('error', formatApiError(error));
      throw error;
    }
  };

  const deleteAsset = async (id: number) => {
    try {
      await api.assets.remove(id);
      await loadAssets();
      notify('success', 'Asset deleted from the backend.');
    } catch (error) {
      notify('error', formatApiError(error));
    }
  };

  const assessAsset = async (id: number, body: { kind: 'tcp' | 'http'; confirm_authorized: boolean; port?: number; timeout_seconds?: number }): Promise<AssetAssessmentResult> => {
    try {
      const result = await api.assets.assess(id, body);
      await loadAssets();
      notify('success', `Authorized ${body.kind.toUpperCase()} assessment completed with status: ${result.status}.`);
      return result;
    } catch (error) {
      notify('error', formatApiError(error));
      throw error;
    }
  };

  const saveCase = async (id: number | null, body: CaseInput) => {
    try {
      if (id) await api.cases.update(id, body);
      else await api.cases.create(body);
      await loadCases();
      await loadGraph();
      notify('success', id ? 'Case updated in the backend.' : 'Case created in the backend.');
    } catch (error) {
      notify('error', formatApiError(error));
      throw error;
    }
  };

  const deleteCase = async (id: number) => {
    try {
      await api.cases.remove(id);
      await loadCases();
      await loadGraph();
      notify('success', 'Case deleted from the backend.');
    } catch (error) {
      notify('error', formatApiError(error));
    }
  };

  const exportCaseReport = async (caseId: number, format: 'json' | 'csv' | 'pdf') => {
    try {
      const blob = await api.reports.download(caseId, format);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
       link.download = `aegis-case-${caseId}.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      notify('success', `${format.toUpperCase()} report exported from the backend.`);
    } catch (error) {
      notify('error', formatApiError(error));
    }
  };

  const statusText = healthLoading ? 'CHECKING BACKEND' : health ? `BACKEND ${health.status.toUpperCase()}` : 'BACKEND UNAVAILABLE';
  const statusReady = Boolean(health && health.status === 'ok');

  return (
    <div className={`app-frame ${mobileNavOpen ? 'nav-open' : ''}`}>
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark"><Shield size={18} /></div>
           <div><strong>AEGIS</strong><span>LOCAL INVESTIGATION</span></div>
          <button className="icon-button mobile-close" onClick={() => setMobileNavOpen(false)} aria-label="Close menu"><X size={18} /></button>
        </div>

        <div className="sidebar-label">WORKSPACE</div>
        <div className="workspace-switcher blacksite-workspace">
          <div className="workspace-avatar"><Landmark size={14} /></div>
          <div><strong>Local command room</strong><span>Real API data only</span></div>
          <ChevronDown size={15} />
        </div>

        <nav className="primary-nav" aria-label="Primary navigation">
          <div className="sidebar-label">OPERATIONS</div>
          {navigationItems.map((item) => {
            const Icon = item.icon;
            return (
              <button key={item.id} className={`nav-item ${activeView === item.id ? 'active' : ''}`} onClick={() => changeView(item.id)} title={item.hint}>
                <Icon size={17} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="sidebar-spacer" />
        <div className="sidebar-progress blacksite-status-card">
          <div className="progress-heading"><span>BACKEND STATUS</span><strong className={statusReady ? 'status-ok' : 'status-muted'}>{health ? health.status.toUpperCase() : '—'}</strong></div>
          <div className="progress-track"><i style={{ width: statusReady ? '100%' : healthLoading ? '50%' : '0%' }} /></div>
          <p><Activity size={14} /> DEMO MODE · REAL DATA ONLY</p>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <button className="icon-button mobile-menu" onClick={() => setMobileNavOpen(true)} aria-label="Open menu"><Menu size={19} /></button>
           <div className="breadcrumb"><span>AEGIS</span><ChevronRight size={14} /><strong>{viewLabels[activeView]}</strong></div>
          <div className="topbar-actions">
            <span className="curated-pill"><span className={`live-dot ${statusReady ? '' : 'status-offline'}`} /> {statusText} · DEMO MODE</span>
            <button className="help-button" onClick={() => changeView('settings')}><CircleHelp size={16} /> Status</button>
          </div>
        </header>

        <div className="page-content">
          <Notice notice={notice} onDismiss={() => setNotice(null)} />
          {activeView === 'command' && <ThreatCommandView events={events} assets={assets} cases={cases} graph={graph} vulnerabilitySearch={vulnerabilitySearch} loading={eventsLoading || assetsLoading || casesLoading || graphLoading || vulnerabilitiesLoading} errors={{ events: eventsError, assets: assetsError, cases: casesError, graph: graphError, vulnerabilities: vulnerabilitiesError }} onRefresh={loadCommandData} onNavigate={changeView} />}
           {activeView === 'intelligence' && <IntelligenceLabView onCaseCreated={async () => { await loadCases(); await loadGraph(); }} onNotify={notify} />}
          {activeView === 'forensics' && <DigitalForensicsView />}
          {activeView === 'timeline' && <EventTimelineView events={events} total={eventsTotal} loading={eventsLoading} error={eventsError} onRefresh={loadEvents} onImport={async (content, format) => { try { return await importEvents(content, format); } catch (error) { notify('error', formatApiError(error)); throw error; } }} />}
          {activeView === 'vulnerabilities' && <VulnerabilityResearchView result={vulnerabilitySearch} loading={vulnerabilitiesLoading} error={vulnerabilitiesError} onSearch={loadVulnerabilities} />}
          {activeView === 'rules' && <DetectionRulesView rules={rules} events={events} loading={rulesLoading} error={rulesError} onRefresh={loadRules} onNotify={notify} />}
           {activeView === 'assets' && <AssetInventoryViewFunctional assets={assets} loading={assetsLoading} error={assetsError} onRefresh={loadAssets} onImport={async (content, format) => { try { return await importAssets(content, format); } catch (error) { notify('error', formatApiError(error)); throw error; } }} onSave={saveAsset} onDelete={deleteAsset} onAssess={assessAsset} />}
           {activeView === 'cases' && <CasesViewFunctional cases={cases} assets={assets} events={events} loading={casesLoading} error={casesError} onRefresh={loadCases} onSave={saveCase} onDelete={deleteCase} onExport={exportCaseReport} />}
           {activeView === 'reports' && <ReportsView cases={cases} loading={casesLoading} error={casesError} onRefresh={loadCases} onExport={exportCaseReport} />}
          {activeView === 'graph' && <AttackGraphView graph={graph} loading={graphLoading} error={graphError} onRefresh={loadGraph} />}
          {activeView === 'settings' && <SettingsView health={health} loading={healthLoading} error={healthError} onRefresh={loadHealth} />}
        </div>
         <footer className="app-footer"><span>AEGIS</span><span>DEMO MODE · REAL API DATA ONLY</span><span>Local-first investigation workspace</span></footer>
      </main>
    </div>
  );
}

interface ThreatCommandProps {
  events: EventRecord[];
  assets: AssetRecord[];
  cases: CaseRecord[];
  graph: GraphResult | null;
  vulnerabilitySearch: VulnerabilitySearchResult | null;
  loading: boolean;
  errors: { events: string | null; assets: string | null; cases: string | null; graph: string | null; vulnerabilities: string | null };
  onRefresh: () => void;
  onNavigate: (view: View) => void;
}

function ThreatCommandView({ events, assets, cases, graph, vulnerabilitySearch, loading, errors, onRefresh, onNavigate }: ThreatCommandProps) {
  const hasError = Object.values(errors).some(Boolean);
  return (
    <div className="view-stack">
      <section className="page-intro split-intro blacksite-hero">
         <div><div className="eyebrow"><span className="eyebrow-mark" /> THREAT COMMAND · DEMO MODE</div><h1>Investigate with<br /><em>evidence, not theater.</em></h1><p>Operational signals below are loaded from the Aegis backend. Empty collections stay empty until you import or create persisted records.</p></div>
        <button className="button dark-button" onClick={onRefresh}><RefreshCw size={15} /> Refresh backend</button>
      </section>

      {hasError && <div className="blacksite-inline-warning"><AlertCircle size={15} /><span>Some backend collections are unavailable. Unavailable data is not represented as a live finding.</span></div>}
      <section className="stat-strip blacksite-stat-strip">
        <StatItem icon={<History size={17} />} tone="indigo" label="EVENTS" value={loading ? '…' : errors.events ? '—' : String(events.length)} detail={errors.events ? 'unavailable' : `${events.length ? 'loaded records' : 'no persisted records'}`} />
        <StatItem icon={<Boxes size={17} />} tone="mint" label="ASSETS" value={loading ? '…' : errors.assets ? '—' : String(assets.length)} detail={errors.assets ? 'unavailable' : 'backend inventory'} />
        <StatItem icon={<FolderKanban size={17} />} tone="amber" label="CASES" value={loading ? '…' : errors.cases ? '—' : String(cases.length)} detail={errors.cases ? 'unavailable' : 'persisted investigations'} />
        <StatItem icon={<ShieldAlert size={17} />} tone="rose" label="NVD RESULTS" value={loading ? '…' : vulnerabilitySearch ? String(vulnerabilitySearch.total) : errors.vulnerabilities ? '—' : '0'} detail={errors.vulnerabilities ? 'unavailable' : 'latest backend search'} />
      </section>

      <section className="blacksite-command-grid">
        <div className="mini-panel blacksite-panel">
          <div className="mini-panel-heading"><div><div className="eyebrow">RECENT EVENTS</div><h2>Event signal</h2></div><button className="text-button" onClick={() => onNavigate('timeline')}>Open timeline <ArrowRight size={14} /></button></div>
          {errors.events ? <ErrorState message={errors.events} onRetry={onRefresh} /> : events.length === 0 ? <EmptyState title="No persisted events" description="Import JSON or CSV telemetry from Event Timeline to populate this view." icon={History} action={<button className="button secondary-button" onClick={() => onNavigate('timeline')}>Import events <ArrowRight size={14} /></button>} /> : <div className="blacksite-list">{events.slice(-5).reverse().map((event) => <EventRow key={event.id} event={event} />)}</div>}
        </div>
        <div className="mini-panel blacksite-panel">
          <div className="mini-panel-heading"><div><div className="eyebrow">ATTACK GRAPH</div><h2>Relationship surface</h2></div><button className="text-button" onClick={() => onNavigate('graph')}>Inspect graph <ArrowRight size={14} /></button></div>
          {errors.graph ? <ErrorState message={errors.graph} onRetry={onRefresh} /> : !graph || graph.nodes.length === 0 ? <EmptyState title="No graph records" description="Graph nodes appear after assets, events, cases, or analyses are persisted." icon={Network} action={<button className="button secondary-button" onClick={() => onNavigate('assets')}>Open inventory <ArrowRight size={14} /></button>} /> : <div className="graph-summary"><div className="graph-metric"><strong>{graph.nodes.length}</strong><span>nodes</span></div><div className="graph-metric"><strong>{graph.edges.length}</strong><span>edges</span></div><div className="graph-source"><GitBranch size={15} /> {graph.source}</div></div>}
        </div>
      </section>

      <section className="section-block">
        <div className="section-heading"><div><div className="eyebrow">PERSISTED WORKSPACE</div><h2>Current investigation surface</h2></div><span className="blacksite-source-chip"><Database size={13} /> sqlite-backed records</span></div>
        <div className="track-grid blacksite-quick-grid">
          <QuickCard icon={<Search size={18} />} title="Run intelligence" detail="Submit an indicator only when you are ready to query the backend." onClick={() => onNavigate('intelligence')} />
          <QuickCard icon={<FileArchive size={18} />} title="Analyze evidence" detail="Hash a local file explicitly or extract IOCs from text." onClick={() => onNavigate('forensics')} />
          <QuickCard icon={<ClipboardList size={18} />} title="Manage cases" detail={`${cases.length} persisted case${cases.length === 1 ? '' : 's'} available.`} onClick={() => onNavigate('cases')} />
        </div>
      </section>
    </div>
  );
}

function StatItem({ icon, tone, label, value, detail }: { icon: React.ReactNode; tone: string; label: string; value: string; detail: string }) {
  return <div className="stat-item"><div className={`stat-icon ${tone}`}>{icon}</div><div><span>{label}</span><strong>{value}</strong></div><small>{detail}</small></div>;
}

function QuickCard({ icon, title, detail, onClick }: { icon: React.ReactNode; title: string; detail: string; onClick: () => void }) {
  return <button className="track-card technical blacksite-quick-card" onClick={onClick}><div className="track-card-top"><div className="track-symbol">{icon}</div><span>OPEN MODULE <ArrowRight size={13} /></span></div><h3>{title}</h3><p>{detail}</p></button>;
}

function EventRow({ event }: { event: EventRecord }) {
  const label = event.event_type || event.type || 'event';
  return <div className="blacksite-list-row"><div className={`blacksite-severity ${statusClass(event.severity)}`} /><div className="blacksite-row-copy"><strong>{label}</strong><span>{event.source || 'unknown source'} · {formatDate(event.timestamp || event.created_at)}</span><small>{event.detail || 'No detail recorded'}</small></div><span className={`blacksite-pill ${statusClass(event.severity)}`}>{event.severity || 'unclassified'}</span></div>;
}

function IntelligenceLabView({ onCaseCreated, onNotify }: { onCaseCreated: () => Promise<void>; onNotify: Notify }) {
  const [kind, setKind] = useState<'ip' | 'url' | 'domain' | 'hash'>('ip');
  const [indicator, setIndicator] = useState('');
  const [result, setResult] = useState<IntelligenceResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [creatingCase, setCreatingCase] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!indicator.trim()) {
      setError('Enter an indicator before submitting an investigation.');
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.intelligence.investigate(kind, indicator.trim()));
    } catch (requestError) {
      setError(formatApiError(requestError));
    } finally {
      setLoading(false);
    }
  };

  const createCase = async () => {
    if (!result) return;
    setCreatingCase(true);
    try {
      await api.cases.create({
        title: `${result.indicator_type.toUpperCase()} investigation · ${result.indicator}`,
        description: result.explanation,
        priority: result.verdict === 'malicious' ? 'critical' : result.verdict === 'suspicious' ? 'high' : 'medium',
        indicators: [result.indicator],
        analyst_notes: `Created from ${result.indicator_type} intelligence lookup. Source attribution: ${(result.source_attribution || []).join(', ') || 'local validation'}.`,
      });
      await onCaseCreated();
      onNotify('success', 'Investigation case created from the persisted intelligence result.');
    } catch (requestError) {
      onNotify('error', formatApiError(requestError));
    } finally {
      setCreatingCase(false);
    }
  };

  return (
    <div className="view-stack">
      <section className="page-intro split-intro"><div><div className="eyebrow"><span className="eyebrow-mark" /> INTELLIGENCE LAB</div><h1>Query one signal.<br /><em>Keep its source visible.</em></h1><p>Investigations are submitted on demand. The backend validates the indicator and returns local/provider findings with source attribution.</p></div><span className="blacksite-demo-label"><Sparkles size={13} /> DEMO MODE · NO SYNTHETIC RESULTS</span></section>
      <section className="blacksite-two-column">
        <form className="mini-panel blacksite-panel blacksite-form-panel" onSubmit={submit}>
          <div className="eyebrow">NEW INVESTIGATION</div>
          <h2>Indicator lookup</h2>
          <p className="blacksite-form-help">Nothing is requested until you submit this form.</p>
          <label className="blacksite-field"><span>Indicator type</span><select value={kind} onChange={(event) => setKind(event.target.value as typeof kind)}><option value="ip">IP address</option><option value="url">URL</option><option value="domain">Domain</option><option value="hash">File hash</option></select></label>
          <label className="blacksite-field"><span>Value</span><input value={indicator} onChange={(event) => setIndicator(event.target.value)} placeholder={kind === 'ip' ? '203.0.113.8' : kind === 'hash' ? 'SHA256 / SHA1 / MD5' : kind === 'url' ? 'https://example.test/path' : 'example.test'} /></label>
          {error && <div className="blacksite-form-error"><AlertCircle size={14} /> {error}</div>}
          <button className="button primary-button" type="submit" disabled={loading}>{loading ? <LoaderCircle size={15} className="spin" /> : <Search size={15} />} {loading ? 'Investigating…' : 'Submit investigation'} <ArrowRight size={14} /></button>
        </form>
        <div className="mini-panel blacksite-panel blacksite-result-panel">
          <div className="mini-panel-heading"><div><div className="eyebrow">SOURCE-ATTRIBUTED RESULT</div><h2>{result ? result.indicator : 'Awaiting submission'}</h2></div>{result && <span className={`blacksite-pill ${statusClass(result.verdict)}`}>{result.verdict}</span>}</div>
           {!result ? <EmptyState title="No investigation run" description="Submit an IP, URL, domain, or hash to see a real backend response." icon={Search} /> : <div className="blacksite-result-content"><div className="blacksite-result-meta"><span>classification <strong>{result.classification}</strong></span><span>valid <strong>{result.valid ? 'yes' : 'no'}</strong></span><span>external queried <strong>{result.externally_queried ? 'yes' : 'no'}</strong></span><span>checked <strong>{formatDate(result.checked_at)}</strong></span></div><p className="blacksite-explanation">{result.explanation}</p><div className="blacksite-finding-list">{(result.results || result.findings || []).map((finding, index) => <div className="blacksite-finding" key={`${finding.source}-${index}`}><div><strong>{finding.source}</strong><span>{finding.status} · {finding.verdict}</span></div><p>{finding.explanation}</p></div>)}</div>{result.blocked_reason && <div className="blacksite-inline-warning"><AlertCircle size={14} /> {result.blocked_reason}</div>}<button className="button secondary-button" onClick={() => void createCase()} disabled={creatingCase}>{creatingCase ? <LoaderCircle size={15} className="spin" /> : <FolderKanban size={15} />} {creatingCase ? 'Creating case…' : 'Create case from result'}</button></div>}
        </div>
      </section>
    </div>
  );
}

function DigitalForensicsView() {
  const [file, setFile] = useState<File | null>(null);
  const [hashResult, setHashResult] = useState<HashResult | null>(null);
  const [hashLoading, setHashLoading] = useState(false);
  const [hashError, setHashError] = useState<string | null>(null);
  const [iocText, setIocText] = useState('');
  const [iocResult, setIocResult] = useState<IocResult | null>(null);
  const [iocLoading, setIocLoading] = useState(false);
  const [iocError, setIocError] = useState<string | null>(null);
  const [logContent, setLogContent] = useState('');
  const [logFormat, setLogFormat] = useState<ImportFormat>('json');
  const [logResult, setLogResult] = useState<LogResult | null>(null);
  const [logLoading, setLogLoading] = useState(false);
  const [logError, setLogError] = useState<string | null>(null);
  const iocFileInput = useRef<HTMLInputElement>(null);
  const logFileInput = useRef<HTMLInputElement>(null);

  const hashFile = async () => {
    if (!file) {
      setHashError('Choose a local file before hashing. Selecting a file does not upload it.');
      return;
    }
    setHashLoading(true);
    setHashError(null);
    try {
      setHashResult(await api.forensics.hashFile(file));
    } catch (error) {
      setHashError(formatApiError(error));
    } finally {
      setHashLoading(false);
    }
  };

  const extract = async (event: FormEvent) => {
    event.preventDefault();
    if (!iocText.trim()) {
      setIocError('Paste text containing indicators before extracting.');
      return;
    }
    setIocLoading(true);
    setIocError(null);
    try {
      setIocResult(await api.forensics.extract(iocText));
    } catch (error) {
      setIocError(formatApiError(error));
    } finally {
      setIocLoading(false);
    }
  };

  const parseLogs = async (event: FormEvent) => {
    event.preventDefault();
    if (!logContent.trim()) {
      setLogError('Paste JSON or CSV log content before parsing.');
      return;
    }
    setLogLoading(true);
    setLogError(null);
    try {
      setLogResult(await api.forensics.logs(logContent, logFormat));
    } catch (error) {
      setLogError(formatApiError(error));
    } finally {
      setLogLoading(false);
    }
  };

  return (
    <div className="view-stack">
      <section className="page-intro"><div><div className="eyebrow"><span className="eyebrow-mark" /> DIGITAL FORENSICS</div><h1>Work locally.<br /><em>Persist only findings.</em></h1><p>File hashing uses an explicit multipart action. IOC and log analysis run against the text you submit and report deterministic backend findings.</p></div></section>
      <section className="blacksite-forensics-grid">
        <div className="mini-panel blacksite-panel">
          <div className="eyebrow">LOCAL FILE HASH</div><h2>Hash evidence</h2><p className="blacksite-form-help">The selected file stays in the browser until you click Hash selected file.</p>
          <label className="blacksite-file-input"><Upload size={16} /><span>{file ? file.name : 'Choose a file'}</span><input type="file" onChange={(event) => { setFile(event.target.files?.[0] || null); setHashResult(null); setHashError(null); }} /></label>
          {file && <div className="blacksite-file-meta">{file.type || 'unknown type'} · {file.size.toLocaleString()} bytes</div>}
          {hashError && <div className="blacksite-form-error"><AlertCircle size={14} /> {hashError}</div>}
          <button className="button primary-button" onClick={hashFile} disabled={hashLoading}>{hashLoading ? <LoaderCircle size={15} className="spin" /> : <Hash size={15} />} {hashLoading ? 'Hashing…' : 'Hash selected file'}</button>
           {hashResult && <div className="blacksite-code-list"><div className="blacksite-result-meta"><span>detected type <strong>{hashResult.metadata?.detected_file_type || 'unknown'}</strong></span><span>size <strong>{hashResult.metadata?.size_bytes?.toLocaleString() || '0'} bytes</strong></span></div>{Object.entries(hashResult.hashes).map(([algorithm, value]) => <div key={algorithm}><span>{algorithm}</span><code>{value}</code></div>)}</div>}
        </div>

        <form className="mini-panel blacksite-panel" onSubmit={extract}>
          <div className="eyebrow">IOC TEXT EXTRACTION</div><h2>Extract indicators</h2><p className="blacksite-form-help">Regex and standard-library validation only; no external lookup is performed.</p>
           <label className="blacksite-file-input compact"><Upload size={14} /><span>Load local text file</span><input ref={iocFileInput} type="file" accept=".txt,.log,.json,.csv,text/plain,application/json,text/csv" onChange={async (event) => { const selected = event.target.files?.[0]; if (selected) setIocText(await selected.text()); }} /></label>
           <textarea className="blacksite-textarea" value={iocText} onChange={(event) => setIocText(event.target.value)} placeholder="Paste an alert, email, or analyst note…" />
          {iocError && <div className="blacksite-form-error"><AlertCircle size={14} /> {iocError}</div>}
          <button className="button dark-button" type="submit" disabled={iocLoading}>{iocLoading ? <LoaderCircle size={15} className="spin" /> : <FileSearch size={15} />} {iocLoading ? 'Extracting…' : 'Extract IOCs'}</button>
          {iocResult && <IocFindings result={iocResult} />}
        </form>

        <form className="mini-panel blacksite-panel blacksite-log-panel" onSubmit={parseLogs}>
          <div className="eyebrow">LOG PARSER</div><h2>Parse and analyze</h2><p className="blacksite-form-help">Submit JSON, JSONL, or CSV. The backend normalizes records and counts failed authentication signals.</p>
          <div className="blacksite-inline-fields"><label className="blacksite-field"><span>Declared format</span><select value={logFormat} onChange={(event) => setLogFormat(event.target.value as ImportFormat)}><option value="json">JSON</option><option value="csv">CSV</option></select></label><span className="blacksite-format-note">Parser accepts JSONL too</span></div>
           <label className="blacksite-file-input compact"><Upload size={14} /><span>Load local JSON/CSV file</span><input ref={logFileInput} type="file" accept=".json,.jsonl,.csv,application/json,text/csv" onChange={async (event) => { const selected = event.target.files?.[0]; if (selected) { setLogContent(await selected.text()); setLogFormat(selected.name.toLowerCase().endsWith('.csv') ? 'csv' : 'json'); } }} /></label>
           <textarea className="blacksite-textarea log" value={logContent} onChange={(event) => setLogContent(event.target.value)} placeholder={'timestamp,source,event_type,status\n2026-01-01T00:00:00Z,host,login,failed'} />
          {logError && <div className="blacksite-form-error"><AlertCircle size={14} /> {logError}</div>}
          <button className="button primary-button" type="submit" disabled={logLoading}>{logLoading ? <LoaderCircle size={15} className="spin" /> : <ClipboardList size={15} />} {logLoading ? 'Parsing…' : 'Parse logs'}</button>
          {logResult && <LogFindings result={logResult} />}
        </form>
      </section>
    </div>
  );
}

function IocFindings({ result }: { result: IocResult }) {
  const groups = [
    ['URLs', result.urls], ['IPv4', result.ipv4], ['IPv6', result.ipv6], ['Domains', result.domains], ['Emails', result.emails], ['CVEs', result.cves],
    ['MD5', result.hashes.md5 || []], ['SHA-1', result.hashes.sha1 || []], ['SHA-256', result.hashes.sha256 || []],
  ] as const;
  return <div className="blacksite-analysis-result"><div className="blacksite-result-meta"><span>analysis <strong>#{result.analysis_id ?? '—'}</strong></span><span>indicators <strong>{Object.values(result.counts).reduce((sum, value) => sum + value, 0)}</strong></span></div>{groups.map(([label, values]) => <div className="blacksite-token-group" key={label}><span>{label}</span><div>{values.length ? values.map((value) => <code key={value}>{value}</code>) : <small>none</small>}</div></div>)}<ObservationList observations={result.observations} /></div>;
}

function LogFindings({ result }: { result: LogResult }) {
  return <div className="blacksite-analysis-result"><div className="blacksite-result-meta"><span>format <strong>{result.format}</strong></span><span>records <strong>{result.total_records}</strong></span><span>failed auth <strong className={result.failed_login_count ? 'danger-text' : ''}>{result.failed_login_count}</strong></span><span>repeated groups <strong>{result.repeated_events?.length || 0}</strong></span><span>frequency flags <strong>{result.unusual_frequency?.length || 0}</strong></span></div><div className="blacksite-log-groups"><div><span>failed by source</span>{Object.keys(result.groups.failed_logins_by_source).length ? Object.entries(result.groups.failed_logins_by_source).map(([key, value]) => <strong key={key}>{key} <em>{value}</em></strong>) : <small>none detected</small>}</div><div><span>failed by user</span>{Object.keys(result.groups.failed_logins_by_username).length ? Object.entries(result.groups.failed_logins_by_username).map(([key, value]) => <strong key={key}>{key} <em>{value}</em></strong>) : <small>none detected</small>}</div></div>{Boolean(result.repeated_events?.length || result.unusual_frequency?.length) && <div className="blacksite-observations">{[...(result.repeated_events || []), ...(result.unusual_frequency || [])].slice(0, 8).map((item, index) => <div key={`${item.group}-${index}`}><span>rule observation</span><p>{item.group} · {item.count} records · {item.rule}</p></div>)}</div>}<ObservationList observations={result.observations} /></div>;
}

function ObservationList({ observations }: { observations: Array<{ source: string; explanation: string }> }) {
  return <div className="blacksite-observations">{observations.map((observation, index) => <div key={`${observation.source}-${index}`}><span>{observation.source}</span><p>{observation.explanation}</p></div>)}</div>;
}

interface EventTimelineProps {
  events: EventRecord[];
  total: number;
  loading: boolean;
  error: string | null;
  onRefresh: () => Promise<void>;
  onImport: (content: string, format: ImportFormat) => Promise<number>;
}

function EventTimelineView({ events, total, loading, error, onRefresh, onImport }: EventTimelineProps) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [source, setSource] = useState('all');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [importing, setImporting] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const filteredEvents = useMemo(() => events.filter((event) => {
    const haystack = `${event.event_type || event.type || ''} ${event.source || ''} ${event.detail || ''}`.toLowerCase();
     const eventTime = event.timestamp ? new Date(event.timestamp).getTime() : null;
     const afterStart = !startDate || (eventTime !== null && eventTime >= new Date(`${startDate}T00:00:00`).getTime());
     const beforeEnd = !endDate || (eventTime !== null && eventTime <= new Date(`${endDate}T23:59:59.999`).getTime());
     return haystack.includes(query.trim().toLowerCase()) && (severity === 'all' || (event.severity || '').toLowerCase() === severity) && (source === 'all' || (event.source || 'unknown') === source) && afterStart && beforeEnd;
   }), [events, query, severity, source, startDate, endDate]);
  const sources = useMemo(() => [...new Set(events.map((event) => event.source || 'unknown'))].sort(), [events]);

  const importFile = async () => {
    if (!file) return;
    setImporting(true);
    try {
      const format: ImportFormat = file.name.toLowerCase().endsWith('.csv') ? 'csv' : 'json';
      await onImport(await file.text(), format);
      setFile(null);
      if (fileInput.current) fileInput.current.value = '';
    } catch {
      // The parent surfaces the API error; leave the selected file available for retry.
    } finally {
      setImporting(false);
    }
  };

  const importSample = async (format: ImportFormat) => {
    setImporting(true);
    try {
      await onImport(SAMPLE_EVENTS[format], format);
    } catch {
      // The parent surfaces the API error.
    } finally {
      setImporting(false);
    }
  };

  return (
    <div className="view-stack">
      <section className="page-intro split-intro"><div><div className="eyebrow"><span className="eyebrow-mark" /> EVENT TIMELINE</div><h1>Read what the backend<br /><em>has actually seen.</em></h1><p>Events are loaded from persisted records and filtered locally for triage. Imports are explicit and immediately written to the backend.</p></div><button className="button dark-button" onClick={() => void onRefresh()}><RefreshCw size={15} /> Refresh events</button></section>
       <section className="mini-panel blacksite-panel blacksite-filter-extra"><div className="blacksite-inline-fields"><label className="blacksite-field"><span>Event source</span><select value={source} onChange={(event) => setSource(event.target.value)}><option value="all">All sources</option>{sources.map((item) => <option key={item} value={item}>{item}</option>)}</select></label><label className="blacksite-field"><span>Start date</span><input type="date" value={startDate} onChange={(event) => setStartDate(event.target.value)} /></label><label className="blacksite-field"><span>End date</span><input type="date" value={endDate} onChange={(event) => setEndDate(event.target.value)} /></label><button className="button secondary-button" onClick={() => { setQuery(''); setSeverity('all'); setSource('all'); setStartDate(''); setEndDate(''); }}><Filter size={15} /> Reset filters</button></div></section>
       <section className="filter-panel blacksite-filter-panel"><div className="filter-top"><div className="track-tabs"><button className={severity === 'all' ? 'active' : ''} onClick={() => setSeverity('all')}>All</button><button className={severity === 'high' ? 'active' : ''} onClick={() => setSeverity('high')}>High</button><button className={severity === 'medium' ? 'active' : ''} onClick={() => setSeverity('medium')}>Medium</button><button className={severity === 'low' ? 'active' : ''} onClick={() => setSeverity('low')}>Low</button></div><span className="result-count"><strong>{filteredEvents.length}</strong> of {total} persisted events</span></div><div className="filter-controls blacksite-filter-controls"><label className="search-field"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter source, type, or detail" /></label></div></section>
      <section className="mini-panel blacksite-panel blacksite-import-panel"><div><div className="eyebrow">IMPORT INTO BACKEND</div><h2>Bring in JSON or CSV telemetry</h2><p>Sample records are clearly labeled and only become live after you choose to persist them.</p></div><div className="blacksite-import-actions"><label className="blacksite-file-input compact"><Upload size={15} /><span>{file ? file.name : 'Choose JSON/CSV'}</span><input ref={fileInput} type="file" accept=".json,.jsonl,.csv,application/json,text/csv" onChange={(event) => setFile(event.target.files?.[0] || null)} /></label><button className="button primary-button" onClick={importFile} disabled={!file || importing}>{importing ? <LoaderCircle size={15} className="spin" /> : <Upload size={15} />} Import selected</button><button className="button secondary-button" onClick={() => void importSample('json')} disabled={importing}>Import sample JSON</button><button className="button secondary-button" onClick={() => void importSample('csv')} disabled={importing}>Import sample CSV</button></div></section>
      {loading ? <LoadingState label="Loading persisted events…" /> : error ? <ErrorState message={error} onRetry={onRefresh} /> : filteredEvents.length === 0 ? <EmptyState title={events.length === 0 ? 'No persisted events' : 'No events match this filter'} description={events.length === 0 ? 'Import JSON or CSV telemetry above to create real timeline records.' : 'Clear the filters to inspect all loaded records.'} icon={History} /> : <section className="blacksite-event-table">{filteredEvents.map((event) => <EventRow key={event.id} event={event} />)}</section>}
    </div>
  );
}

interface VulnerabilityProps {
  result: VulnerabilitySearchResult | null;
  loading: boolean;
  error: string | null;
  onSearch: (query: string, filters?: { severity?: string; published_after?: string; published_before?: string }) => Promise<void>;
}

function VulnerabilityResearchView({ result, loading, error, onSearch }: VulnerabilityProps) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [publishedAfter, setPublishedAfter] = useState('');
  const [publishedBefore, setPublishedBefore] = useState('');
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void onSearch(query, { severity: severity || undefined, published_after: publishedAfter ? `${publishedAfter}T00:00:00.000Z` : undefined, published_before: publishedBefore ? `${publishedBefore}T23:59:59.999Z` : undefined });
  };
  return (
    <div className="view-stack">
      <section className="page-intro"><div><div className="eyebrow"><span className="eyebrow-mark" /> VULNERABILITY RESEARCH</div><h1>Search the NVD.<br /><em>Show empty honestly.</em></h1><p>Searches are sent through the backend NVD adapter. A missing configuration or upstream failure is shown as unavailable, never as a clean result.</p></div></section>
       <form className="filter-panel blacksite-search-panel" onSubmit={submit}><div className="filter-top"><div><div className="eyebrow">NVD BACKEND QUERY</div><h2>Find a CVE or keyword</h2></div>{result && <span className="result-count"><strong>{result.total}</strong> results · source {result.source}</span>}</div><div className="filter-controls"><label className="search-field"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="CVE-2024-1234 or product keyword" /></label><select className="graph-filter-select" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">Any severity</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select><label className="blacksite-field"><span>Published after</span><input type="date" value={publishedAfter} onChange={(event) => setPublishedAfter(event.target.value)} /></label><label className="blacksite-field"><span>Published before</span><input type="date" value={publishedBefore} onChange={(event) => setPublishedBefore(event.target.value)} /></label><button className="button primary-button" type="submit" disabled={loading}>{loading ? <LoaderCircle size={15} className="spin" /> : <Search size={15} />} Search NVD</button></div></form>
      {loading ? <LoadingState label="Querying NVD through backend…" /> : error ? <ErrorState message={error} /> : !result ? <EmptyState title="No NVD search run" description="Enter a CVE identifier or keyword and submit the backend search." icon={ShieldAlert} /> : result.results.length === 0 ? <EmptyState title="NVD returned no matches" description="The backend search completed without any matching vulnerability records." icon={ShieldAlert} /> : <section className="blacksite-vulnerability-grid">{result.results.map((vulnerability) => <article className="mini-panel blacksite-panel blacksite-vulnerability-card" key={vulnerability.id}><div className="blacksite-vulnerability-top"><span className="blacksite-cve">{vulnerability.id}</span><span className={`blacksite-pill ${statusClass(vulnerability.severity)}`}>{vulnerability.severity || 'unrated'}</span></div><p>{vulnerability.description || 'No English description returned by NVD.'}</p><div className="blacksite-result-meta"><span>CVSS <strong>{vulnerability.cvss_score ?? '—'}</strong></span><span>published <strong>{formatDate(vulnerability.published)}</strong></span><span>refs <strong>{vulnerability.references.length}</strong></span></div></article>)}</section>}
    </div>
  );
}

interface DetectionRulesProps {
  rules: RuleRecord[];
  events: EventRecord[];
  loading: boolean;
  error: string | null;
  onRefresh: () => Promise<void>;
  onNotify: Notify;
}

interface RuleDraft {
  name: string;
  description: string;
  field: string;
  operator: string;
  value: string;
  enabled: boolean;
}

const emptyRuleDraft: RuleDraft = { name: '', description: '', field: 'severity', operator: 'equals', value: '', enabled: true };

function DetectionRulesView({ rules, events, loading, error, onRefresh, onNotify }: DetectionRulesProps) {
  const [draft, setDraft] = useState<RuleDraft>(emptyRuleDraft);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  const [testResults, setTestResults] = useState<Record<number, RuleTestResult>>({});

  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (!draft.name.trim() || !draft.field.trim() || !draft.value.trim()) {
      onNotify('error', 'Rule name, condition field, and condition value are required.');
      return;
    }
    setSaving(true);
    try {
      const body = { name: draft.name.trim(), description: draft.description.trim() || undefined, enabled: draft.enabled, condition: { field: draft.field.trim(), operator: draft.operator, value: draft.value } as ConditionNode };
      if (editingId) await api.rules.update(editingId, body);
      else await api.rules.create(body);
      await onRefresh();
      setDraft(emptyRuleDraft);
      setEditingId(null);
      onNotify('success', editingId ? 'Detection rule updated in the backend.' : 'Detection rule created in the backend.');
    } catch (error) {
      onNotify('error', formatApiError(error));
    } finally {
      setSaving(false);
    }
  };

  const edit = (rule: RuleRecord) => {
    const condition = rule.condition_tree || rule.condition;
    setEditingId(rule.id);
    setDraft({ name: rule.name, description: rule.description || '', field: condition.field || '', operator: condition.operator || 'equals', value: textValue(condition.value) === '—' ? '' : textValue(condition.value), enabled: rule.enabled });
  };

  const toggle = async (rule: RuleRecord) => {
    try {
      await api.rules.update(rule.id, { enabled: !rule.enabled });
      await onRefresh();
      onNotify('success', `Rule ${rule.enabled ? 'disabled' : 'enabled'} in the backend.`);
    } catch (error) {
      onNotify('error', formatApiError(error));
    }
  };

  const remove = async (rule: RuleRecord) => {
    if (!window.confirm(`Delete rule “${rule.name}”?`)) return;
    try {
      await api.rules.remove(rule.id);
      await onRefresh();
      onNotify('success', 'Detection rule deleted from the backend.');
    } catch (error) {
      onNotify('error', formatApiError(error));
    }
  };

  const test = async (rule: RuleRecord) => {
    try {
      const result = await api.rules.test(rule.id);
      setTestResults((current) => ({ ...current, [rule.id]: result }));
    } catch (error) {
      onNotify('error', formatApiError(error));
    }
  };

  return (
    <div className="view-stack">
      <section className="page-intro split-intro"><div><div className="eyebrow"><span className="eyebrow-mark" /> DETECTION RULES</div><h1>Test logic against<br /><em>persisted event data.</em></h1><p>Rules are data-only condition trees evaluated by the backend. Test results report the actual event count and match IDs returned by the API.</p></div><span className="blacksite-source-chip"><Database size={13} /> {events.length} loaded events</span></section>
      <section className="blacksite-two-column">
        <form className="mini-panel blacksite-panel blacksite-form-panel" onSubmit={save}><div className="eyebrow">{editingId ? 'EDIT RULE' : 'CREATE RULE'}</div><h2>{editingId ? 'Update detection rule' : 'New detection rule'}</h2><label className="blacksite-field"><span>Name</span><input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder="Failed login burst" /></label><label className="blacksite-field"><span>Description</span><textarea value={draft.description} onChange={(event) => setDraft({ ...draft, description: event.target.value })} placeholder="What should this rule explain?" /></label><div className="blacksite-inline-fields"><label className="blacksite-field"><span>Field</span><input value={draft.field} onChange={(event) => setDraft({ ...draft, field: event.target.value })} placeholder="severity or payload.status" /></label><label className="blacksite-field"><span>Operator</span><select value={draft.operator} onChange={(event) => setDraft({ ...draft, operator: event.target.value })}><option value="equals">equals</option><option value="not_equals">not equals</option><option value="contains">contains</option><option value="starts_with">starts with</option><option value="gt">greater than</option><option value="gte">at least</option><option value="lt">less than</option><option value="lte">at most</option></select></label></div><label className="blacksite-field"><span>Value</span><input value={draft.value} onChange={(event) => setDraft({ ...draft, value: event.target.value })} placeholder="high" /></label><label className="blacksite-check"><input type="checkbox" checked={draft.enabled} onChange={(event) => setDraft({ ...draft, enabled: event.target.checked })} /> Enabled for backend evaluation</label><div className="blacksite-form-actions"><button className="button primary-button" type="submit" disabled={saving}>{saving ? <LoaderCircle size={15} className="spin" /> : editingId ? <Check size={15} /> : <Plus size={15} />} {editingId ? 'Save rule' : 'Create rule'}</button>{editingId && <button className="button secondary-button" type="button" onClick={() => { setEditingId(null); setDraft(emptyRuleDraft); }}>Cancel</button>}</div></form>
        <div className="mini-panel blacksite-panel"><div className="mini-panel-heading"><div><div className="eyebrow">PERSISTED RULES</div><h2>Rules in backend</h2></div><button className="icon-button" onClick={() => void onRefresh()} aria-label="Refresh rules"><RefreshCw size={16} /></button></div>{loading ? <LoadingState label="Loading rules…" /> : error ? <ErrorState message={error} onRetry={onRefresh} /> : rules.length === 0 ? <EmptyState title="No detection rules" description="Create a rule to evaluate it against persisted events." icon={TerminalSquare} /> : <div className="blacksite-rule-list">{rules.map((rule) => <RuleCard key={rule.id} rule={rule} result={testResults[rule.id]} onEdit={() => edit(rule)} onToggle={() => void toggle(rule)} onDelete={() => void remove(rule)} onTest={() => void test(rule)} />)}</div>}</div>
      </section>
    </div>
  );
}

function RuleCard({ rule, result, onEdit, onToggle, onDelete, onTest }: { rule: RuleRecord; result?: RuleTestResult; onEdit: () => void; onToggle: () => void; onDelete: () => void; onTest: () => void }) {
  return <article className="blacksite-rule-card"><div className="blacksite-rule-head"><div><strong>{rule.name}</strong><span>{rule.description || 'No description'}</span></div><span className={`blacksite-pill ${rule.enabled ? 'success' : 'neutral'}`}>{rule.enabled ? 'enabled' : 'disabled'}</span></div><div className="blacksite-condition"><TerminalSquare size={13} /> {describeCondition(rule.condition_tree || rule.condition)}</div><div className="blacksite-card-actions"><button className="text-button" onClick={onTest}><Activity size={13} /> Test against events</button><button className="icon-button" onClick={onToggle} title={rule.enabled ? 'Disable rule' : 'Enable rule'}><PowerIcon enabled={rule.enabled} /></button><button className="icon-button" onClick={onEdit} title="Edit rule"><Pencil size={14} /></button><button className="icon-button danger-icon" onClick={onDelete} title="Delete rule"><Trash2 size={14} /></button></div>{result && <div className="blacksite-test-result"><div className="blacksite-result-meta"><span>evaluated <strong>{result.evaluated_count}</strong></span><span>matched <strong className={result.matched_count ? 'danger-text' : ''}>{result.matched_count}</strong></span><span>backend rule #{result.rule_id}</span></div><p>{result.enabled ? `Backend evaluated persisted events against “${describeCondition(rule.condition)}”.` : 'The backend returned this rule as disabled, so no event can match it.'}</p>{result.matches.length ? <div className="blacksite-match-list">{result.matches.slice(0, 8).map((match) => <span key={match.event_id} title={match.explanation}><Check size={12} /> event #{match.event_id} · {match.matched ? 'matched' : 'not matched'} · {match.explanation || match.event_type || 'event'}</span>)}</div> : <small>No persisted events were evaluated.</small>}</div>}</article>;
}

function PowerIcon({ enabled }: { enabled: boolean }) {
  return <span className={`power-icon ${enabled ? 'on' : ''}`} aria-hidden="true" />;
}

interface AssetViewProps {
  assets: AssetRecord[];
  loading: boolean;
  error: string | null;
  onRefresh: () => Promise<void>;
  onImport: (content: string, format: ImportFormat) => Promise<number>;
  onSave: (id: number | null, body: AssetInput) => Promise<void>;
  onDelete: (id: number) => Promise<void>;
  onAssess: (id: number, body: { kind: 'tcp' | 'http'; confirm_authorized: boolean; port?: number; timeout_seconds?: number }) => Promise<AssetAssessmentResult>;
}

interface AssetDraft {
  name: string;
  hostname: string;
  ip: string;
  kind: string;
  risk: string;
  status: string;
  operating_system: string;
  owner: string;
  notes: string;
}

const emptyAssetDraft: AssetDraft = { name: '', hostname: '', ip: '', kind: '', risk: '', status: '', operating_system: '', owner: '', notes: '' };

function AssetInventoryView({ assets, loading, error, onRefresh, onImport, onSave, onDelete, onAssess }: AssetViewProps) {
  const [draft, setDraft] = useState<AssetDraft>(emptyAssetDraft);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [importing, setImporting] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (!draft.name.trim()) return;
    setSaving(true);
    try {
      await onSave(editingId, { ...draft, name: draft.name.trim() });
      setDraft(emptyAssetDraft);
      setEditingId(null);
    } catch {
      // The parent reports the failure.
    } finally {
      setSaving(false);
    }
  };

  const edit = (asset: AssetRecord) => {
    setEditingId(asset.id);
    setDraft({ name: asset.name, hostname: asset.hostname || '', ip: asset.ip || '', kind: asset.kind || '', risk: asset.risk || '', status: asset.status || '', operating_system: asset.operating_system || '', owner: asset.owner || '', notes: asset.notes || '' });
  };

  const importFile = async () => {
    if (!file) return;
    setImporting(true);
    try {
      await onImport(await file.text(), file.name.toLowerCase().endsWith('.csv') ? 'csv' : 'json');
      setFile(null);
      if (fileInput.current) fileInput.current.value = '';
    } catch {
      // The parent reports the failure.
    } finally {
      setImporting(false);
    }
  };

  const importSample = async (format: ImportFormat) => {
    setImporting(true);
    try { await onImport(SAMPLE_ASSETS[format], format); } catch { /* parent reports */ } finally { setImporting(false); }
  };

  return (
    <div className="view-stack">
      <section className="page-intro split-intro"><div><div className="eyebrow"><span className="eyebrow-mark" /> ASSET INVENTORY</div><h1>Know what exists<br /><em>before you map risk.</em></h1><p>Create, edit, delete, and import inventory records backed by the API. This view never invents an asset when the database is empty.</p></div><button className="button dark-button" onClick={() => void onRefresh()}><RefreshCw size={15} /> Refresh assets</button></section>
      <section className="mini-panel blacksite-panel blacksite-import-panel"><div><div className="eyebrow">JSON / CSV IMPORT</div><h2>Import inventory</h2><p>Choose a file or explicitly persist a labeled sample record.</p></div><div className="blacksite-import-actions"><label className="blacksite-file-input compact"><Upload size={15} /><span>{file ? file.name : 'Choose JSON/CSV'}</span><input ref={fileInput} type="file" accept=".json,.csv,application/json,text/csv" onChange={(event) => setFile(event.target.files?.[0] || null)} /></label><button className="button primary-button" onClick={importFile} disabled={!file || importing}>{importing ? <LoaderCircle size={15} className="spin" /> : <Upload size={15} />} Import selected</button><button className="button secondary-button" onClick={() => void importSample('json')} disabled={importing}>Import sample JSON</button><button className="button secondary-button" onClick={() => void importSample('csv')} disabled={importing}>Import sample CSV</button></div></section>
      <section className="blacksite-two-column">
         <form className="mini-panel blacksite-panel blacksite-form-panel" onSubmit={save}><div className="eyebrow">{editingId ? 'EDIT ASSET' : 'CREATE ASSET'}</div><h2>{editingId ? 'Update inventory record' : 'New inventory record'}</h2><label className="blacksite-field"><span>Name *</span><input required value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder="Web server 01" /></label><div className="blacksite-inline-fields"><label className="blacksite-field"><span>Hostname</span><input value={draft.hostname} onChange={(event) => setDraft({ ...draft, hostname: event.target.value })} placeholder="web-01" /></label><label className="blacksite-field"><span>IP</span><input value={draft.ip} onChange={(event) => setDraft({ ...draft, ip: event.target.value })} placeholder="192.0.2.10" /></label></div><div className="blacksite-inline-fields"><label className="blacksite-field"><span>Kind</span><input value={draft.kind} onChange={(event) => setDraft({ ...draft, kind: event.target.value })} placeholder="server" /></label><label className="blacksite-field"><span>Risk</span><select value={draft.risk} onChange={(event) => setDraft({ ...draft, risk: event.target.value })}><option value="">Unclassified</option><option>low</option><option>medium</option><option>high</option><option>critical</option><option>unknown</option></select></label></div><div className="blacksite-inline-fields"><label className="blacksite-field"><span>Operating system</span><input value={draft.operating_system} onChange={(event) => setDraft({ ...draft, operating_system: event.target.value })} placeholder="Linux / Windows" /></label><label className="blacksite-field"><span>Owner / team</span><input value={draft.owner} onChange={(event) => setDraft({ ...draft, owner: event.target.value })} placeholder="Platform engineering" /></label></div><label className="blacksite-field"><span>Status</span><input value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value })} placeholder="observed / retired" /></label><label className="blacksite-field"><span>Notes</span><textarea value={draft.notes} onChange={(event) => setDraft({ ...draft, notes: event.target.value })} placeholder="Authorized scope, software, or assessment context" /></label><div className="blacksite-form-actions"><button className="button primary-button" type="submit" disabled={saving}>{saving ? <LoaderCircle size={15} className="spin" /> : editingId ? <Check size={15} /> : <Plus size={15} />} {editingId ? 'Save asset' : 'Create asset'}</button>{editingId && <button className="button secondary-button" type="button" onClick={() => { setEditingId(null); setDraft(emptyAssetDraft); }}>Cancel</button>}</div></form>
        <div className="mini-panel blacksite-panel"><div className="mini-panel-heading"><div><div className="eyebrow">PERSISTED INVENTORY</div><h2>{assets.length} asset{assets.length === 1 ? '' : 's'}</h2></div><button className="icon-button" onClick={() => void onRefresh()} aria-label="Refresh assets"><RefreshCw size={16} /></button></div>{loading ? <LoadingState label="Loading assets…" /> : error ? <ErrorState message={error} onRetry={onRefresh} /> : assets.length === 0 ? <EmptyState title="No persisted assets" description="Create an asset or import JSON/CSV inventory to populate this list." icon={Boxes} /> : <div className="blacksite-asset-list">{assets.map((asset) => <article className="blacksite-asset-card" key={asset.id}><div className="blacksite-asset-icon"><Boxes size={16} /></div><div className="blacksite-row-copy"><strong>{asset.name}</strong><span>{asset.hostname || 'no hostname'} · {asset.ip || 'no IP'}</span><small>{asset.kind || 'unclassified'} · {asset.status || 'status unknown'}</small></div><span className={`blacksite-pill ${statusClass(asset.risk)}`}>{asset.risk || 'unclassified'}</span><div className="blacksite-card-actions"><button className="icon-button" onClick={() => edit(asset)} title="Edit asset"><Pencil size={14} /></button><button className="icon-button danger-icon" onClick={() => void onDelete(asset.id)} title="Delete asset"><Trash2 size={14} /></button></div></article>)}</div>}</div>
      </section>
    </div>
  );
}

function AssetInventoryViewFunctional({ assets, loading, error, onRefresh, onImport, onSave, onDelete, onAssess }: AssetViewProps) {
  const [draft, setDraft] = useState<AssetDraft>(emptyAssetDraft);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [importing, setImporting] = useState(false);
  const [assessingId, setAssessingId] = useState<number | null>(null);
  const [assetQuery, setAssetQuery] = useState('');
  const [assetRisk, setAssetRisk] = useState('');
  const visibleAssets = useMemo(() => assets.filter((asset) => `${asset.name} ${asset.hostname || ''} ${asset.ip || ''} ${asset.owner || ''}`.toLowerCase().includes(assetQuery.toLowerCase()) && (!assetRisk || (asset.risk || '').toLowerCase() === assetRisk)), [assets, assetQuery, assetRisk]);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (!draft.name.trim()) return;
    setSaving(true);
    try {
      await onSave(editingId, { ...draft, name: draft.name.trim() });
      setDraft(emptyAssetDraft);
      setEditingId(null);
    } catch {
      // Parent surfaces the API failure.
    } finally {
      setSaving(false);
    }
  };

  const importSelected = async () => {
    if (!selectedFile) return;
    setImporting(true);
    try {
      await onImport(await selectedFile.text(), selectedFile.name.toLowerCase().endsWith('.csv') ? 'csv' : 'json');
      setSelectedFile(null);
    } catch {
      // Parent surfaces the API failure.
    } finally {
      setImporting(false);
    }
  };

  const runAssessment = async (asset: AssetRecord) => {
    const rawPort = window.prompt(`Authorized TCP port for ${asset.name}`, '443');
    const port = rawPort ? Number(rawPort) : NaN;
    if (!Number.isInteger(port) || port < 1 || port > 65535) return;
    if (!window.confirm(`Confirm you are authorized to assess ${asset.name} on TCP/${port}?`)) return;
    setAssessingId(asset.id);
    try {
      await onAssess(asset.id, { kind: 'tcp', port, confirm_authorized: true });
    } catch {
      // Parent surfaces the API failure.
    } finally {
      setAssessingId(null);
    }
  };

  return <div className="view-stack"><section className="page-intro split-intro"><div><div className="eyebrow"><span className="eyebrow-mark" /> ASSET INVENTORY</div><h1>Know what exists<br /><em>before you map risk.</em></h1><p>Inventory records are persisted in SQLite. Active checks are single-target, explicitly authorized, and limited to safe connectivity metadata.</p></div><button className="button dark-button" onClick={() => void onRefresh()}><RefreshCw size={15} /> Refresh assets</button></section><section className="mini-panel blacksite-panel blacksite-import-panel"><div><div className="eyebrow">JSON / CSV IMPORT</div><h2>Import inventory</h2><p>Files are read in the browser and submitted only when you choose import.</p></div><div className="blacksite-import-actions"><label className="blacksite-file-input compact"><Upload size={15} /><span>{selectedFile ? selectedFile.name : 'Choose JSON/CSV'}</span><input type="file" accept=".json,.csv,application/json,text/csv" onChange={(event) => setSelectedFile(event.target.files?.[0] || null)} /></label><button className="button primary-button" onClick={() => void importSelected()} disabled={!selectedFile || importing}>{importing ? <LoaderCircle size={15} className="spin" /> : <Upload size={15} />} Import selected</button></div></section><section className="blacksite-two-column"><form className="mini-panel blacksite-panel blacksite-form-panel" onSubmit={save}><div className="eyebrow">{editingId ? 'EDIT ASSET' : 'CREATE ASSET'}</div><h2>{editingId ? 'Update inventory record' : 'New inventory record'}</h2><label className="blacksite-field"><span>Name *</span><input required value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder="Web server 01" /></label><div className="blacksite-inline-fields"><label className="blacksite-field"><span>Hostname</span><input value={draft.hostname} onChange={(event) => setDraft({ ...draft, hostname: event.target.value })} placeholder="web-01" /></label><label className="blacksite-field"><span>IP</span><input value={draft.ip} onChange={(event) => setDraft({ ...draft, ip: event.target.value })} placeholder="192.0.2.10" /></label></div><div className="blacksite-inline-fields"><label className="blacksite-field"><span>Operating system</span><input value={draft.operating_system} onChange={(event) => setDraft({ ...draft, operating_system: event.target.value })} placeholder="Linux / Windows" /></label><label className="blacksite-field"><span>Owner / team</span><input value={draft.owner} onChange={(event) => setDraft({ ...draft, owner: event.target.value })} placeholder="Platform engineering" /></label></div><label className="blacksite-field"><span>Kind / criticality</span><input value={draft.kind} onChange={(event) => setDraft({ ...draft, kind: event.target.value })} placeholder="server · high" /></label><label className="blacksite-field"><span>Notes</span><textarea value={draft.notes} onChange={(event) => setDraft({ ...draft, notes: event.target.value })} placeholder="Authorized scope, software, or assessment context" /></label><div className="blacksite-form-actions"><button className="button primary-button" type="submit" disabled={saving}>{saving ? <LoaderCircle size={15} className="spin" /> : editingId ? <Check size={15} /> : <Plus size={15} />} {editingId ? 'Save asset' : 'Create asset'}</button>{editingId && <button className="button secondary-button" type="button" onClick={() => { setEditingId(null); setDraft(emptyAssetDraft); }}>Cancel</button>}</div></form><div className="mini-panel blacksite-panel"><div className="mini-panel-heading"><div><div className="eyebrow">PERSISTED INVENTORY</div><h2>{assets.length} asset{assets.length === 1 ? '' : 's'}</h2></div><button className="icon-button" onClick={() => void onRefresh()} aria-label="Refresh assets"><RefreshCw size={16} /></button></div><div className="filter-controls blacksite-filter-controls"><label className="search-field"><Search size={15} /><input value={assetQuery} onChange={(event) => setAssetQuery(event.target.value)} placeholder="Search name, host, IP, owner" /></label><select className="graph-filter-select" value={assetRisk} onChange={(event) => setAssetRisk(event.target.value)}><option value="">All risk</option><option>low</option><option>medium</option><option>high</option><option>critical</option><option>unknown</option></select></div>{loading ? <LoadingState label="Loading assets…" /> : error ? <ErrorState message={error} onRetry={onRefresh} /> : assets.length === 0 ? <EmptyState title="No persisted assets" description="Create an asset or import JSON/CSV inventory to populate this list." icon={Boxes} /> : visibleAssets.length === 0 ? <EmptyState title="No matching assets" description="Change the inventory search or risk filter." icon={Search} /> : <div className="blacksite-asset-list">{visibleAssets.map((asset) => <article className="blacksite-asset-card" key={asset.id}><div className="blacksite-asset-icon"><Boxes size={16} /></div><div className="blacksite-row-copy"><strong>{asset.name}</strong><span>{asset.hostname || 'no hostname'} · {asset.ip || 'no IP'}</span><small>{asset.operating_system || 'OS unknown'} · {asset.owner || 'owner unknown'} · {asset.status || 'status unknown'}</small></div><span className={`blacksite-pill ${statusClass(asset.risk)}`}>{asset.risk || 'unclassified'}</span><div className="blacksite-card-actions"><button className="text-button" onClick={() => void runAssessment(asset)} disabled={assessingId === asset.id}>{assessingId === asset.id ? <LoaderCircle size={13} className="spin" /> : <Activity size={13} />} {assessingId === asset.id ? 'Assessing…' : 'Assess TCP'}</button><button className="icon-button" onClick={() => { setEditingId(asset.id); setDraft({ name: asset.name, hostname: asset.hostname || '', ip: asset.ip || '', kind: asset.kind || '', risk: asset.risk || '', status: asset.status || '', operating_system: asset.operating_system || '', owner: asset.owner || '', notes: asset.notes || '' }); }} title="Edit asset"><Pencil size={14} /></button><button className="icon-button danger-icon" onClick={() => void onDelete(asset.id)} title="Delete asset"><Trash2 size={14} /></button></div></article>)}</div>}</div></section></div>;
}

interface CasesProps {
  cases: CaseRecord[];
  assets: AssetRecord[];
  events: EventRecord[];
  loading: boolean;
  error: string | null;
  onRefresh: () => Promise<void>;
  onSave: (id: number | null, body: CaseInput) => Promise<void>;
  onDelete: (id: number) => Promise<void>;
  onExport: (id: number, format: 'json' | 'csv' | 'pdf') => Promise<void>;
}

interface CaseDraft {
  title: string;
  description: string;
  status: string;
  priority: string;
  assignee: string;
  assetIds: number[];
  eventIds: number[];
  indicators: string;
  vulnerabilityIds: string;
  analystNotes: string;
}

const emptyCaseDraft: CaseDraft = { title: '', description: '', status: 'open', priority: 'medium', assignee: '', assetIds: [], eventIds: [], indicators: '', vulnerabilityIds: '', analystNotes: '' };

function CasesView({ cases, assets, events, loading, error, onRefresh, onSave, onDelete, onExport }: CasesProps) {
  const [draft, setDraft] = useState<CaseDraft>(emptyCaseDraft);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (!draft.title.trim()) return;
    setSaving(true);
    try {
      await onSave(editingId, { title: draft.title.trim(), description: draft.description.trim() || undefined, status: draft.status, priority: draft.priority, assignee: draft.assignee.trim() || undefined, asset_ids: draft.assetIds, event_ids: draft.eventIds, indicators: draft.indicators.split(/[,\n]/).map((item) => item.trim()).filter(Boolean), vulnerability_ids: draft.vulnerabilityIds.split(/[,\n]/).map((item) => item.trim()).filter(Boolean), analyst_notes: draft.analystNotes.trim() || undefined });
      setDraft(emptyCaseDraft);
      setEditingId(null);
    } catch {
      // The parent reports the failure.
    } finally {
      setSaving(false);
    }
  };

  const edit = (item: CaseRecord) => {
    setEditingId(item.id);
    setDraft({ title: item.title, description: item.description || '', status: item.status, priority: item.priority, assignee: item.assignee || '', assetIds: item.asset_ids || [], eventIds: item.event_ids || [], indicators: (item.indicators || item.related_indicators || []).join('\n'), vulnerabilityIds: (item.vulnerability_ids || []).join('\n'), analystNotes: item.analyst_notes || '' });
  };

  const selectedIds = (event: ChangeEvent<HTMLSelectElement>) => Array.from(event.target.selectedOptions).map((option) => Number(option.value));

  return (
    <div className="view-stack">
      <section className="page-intro split-intro"><div><div className="eyebrow"><span className="eyebrow-mark" /> CASE MANAGEMENT</div><h1>Keep the thread<br /><em>attached to evidence.</em></h1><p>Cases are loaded and persisted through the backend. Associate real assets and events, then export a report from the selected case.</p></div><button className="button dark-button" onClick={() => void onRefresh()}><RefreshCw size={15} /> Refresh cases</button></section>
      <section className="blacksite-two-column">
        <form className="mini-panel blacksite-panel blacksite-form-panel" onSubmit={save}><div className="eyebrow">{editingId ? 'EDIT CASE' : 'CREATE CASE'}</div><h2>{editingId ? 'Update investigation' : 'New investigation'}</h2><label className="blacksite-field"><span>Title *</span><input required value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} placeholder="Suspicious authentication activity" /></label><label className="blacksite-field"><span>Description</span><textarea value={draft.description} onChange={(event) => setDraft({ ...draft, description: event.target.value })} placeholder="Scope and current hypothesis" /></label><div className="blacksite-inline-fields"><label className="blacksite-field"><span>Status</span><select value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value })}><option>open</option><option>investigating</option><option>closed</option><option>on_hold</option></select></label><label className="blacksite-field"><span>Priority</span><select value={draft.priority} onChange={(event) => setDraft({ ...draft, priority: event.target.value })}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label></div><label className="blacksite-field"><span>Assignee</span><input value={draft.assignee} onChange={(event) => setDraft({ ...draft, assignee: event.target.value })} placeholder="Operator or team" /></label><label className="blacksite-field"><span>Assets <small>Ctrl/Cmd-click for multiple</small></span><select multiple value={draft.assetIds.map(String)} onChange={(event) => setDraft({ ...draft, assetIds: selectedIds(event) })}>{assets.map((asset) => <option key={asset.id} value={asset.id}>#{asset.id} · {asset.name}</option>)}</select></label><label className="blacksite-field"><span>Events <small>Ctrl/Cmd-click for multiple</small></span><select multiple value={draft.eventIds.map(String)} onChange={(event) => setDraft({ ...draft, eventIds: selectedIds(event) })}>{events.map((item) => <option key={item.id} value={item.id}>#{item.id} · {item.event_type || item.type || 'event'}</option>)}</select></label><div className="blacksite-form-actions"><button className="button primary-button" type="submit" disabled={saving}>{saving ? <LoaderCircle size={15} className="spin" /> : editingId ? <Check size={15} /> : <Plus size={15} />} {editingId ? 'Save case' : 'Create case'}</button>{editingId && <button className="button secondary-button" type="button" onClick={() => { setEditingId(null); setDraft(emptyCaseDraft); }}>Cancel</button>}</div></form>
        <div className="mini-panel blacksite-panel"><div className="mini-panel-heading"><div><div className="eyebrow">PERSISTED CASES</div><h2>{cases.length} case{cases.length === 1 ? '' : 's'}</h2></div><button className="icon-button" onClick={() => void onRefresh()} aria-label="Refresh cases"><RefreshCw size={16} /></button></div>{loading ? <LoadingState label="Loading cases…" /> : error ? <ErrorState message={error} onRetry={onRefresh} /> : cases.length === 0 ? <EmptyState title="No persisted cases" description="Create a case to associate assets, events, and exported reports." icon={FolderKanban} /> : <div className="blacksite-case-list">{cases.map((item) => <CaseCard key={item.id} item={item} onEdit={() => edit(item)} onDelete={() => void onDelete(item.id)} onExport={(format) => void onExport(item.id, format)} />)}</div>}</div>
      </section>
    </div>
  );
}

function CasesViewFunctional({ cases, assets, events, loading, error, onRefresh, onSave, onDelete, onExport }: CasesProps) {
  const [draft, setDraft] = useState<CaseDraft>(emptyCaseDraft);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  const selectedIds = (event: ChangeEvent<HTMLSelectElement>) => Array.from(event.target.selectedOptions).map((option) => Number(option.value));
  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (!draft.title.trim()) return;
    setSaving(true);
    try {
      await onSave(editingId, { title: draft.title.trim(), description: draft.description.trim() || undefined, status: draft.status, priority: draft.priority, assignee: draft.assignee.trim() || undefined, asset_ids: draft.assetIds, event_ids: draft.eventIds, indicators: draft.indicators.split(/[,\n]/).map((value) => value.trim()).filter(Boolean), vulnerability_ids: draft.vulnerabilityIds.split(/[,\n]/).map((value) => value.trim()).filter(Boolean), analyst_notes: draft.analystNotes.trim() || undefined });
      setDraft(emptyCaseDraft); setEditingId(null);
    } catch {
      // Parent surfaces the API failure.
    } finally { setSaving(false); }
  };
  const edit = (item: CaseRecord) => { setEditingId(item.id); setDraft({ title: item.title, description: item.description || '', status: item.status, priority: item.priority, assignee: item.assignee || '', assetIds: item.asset_ids || [], eventIds: item.event_ids || [], indicators: (item.indicators || item.related_indicators || []).join('\n'), vulnerabilityIds: (item.vulnerability_ids || []).join('\n'), analystNotes: item.analyst_notes || '' }); };
  return <div className="view-stack"><section className="page-intro split-intro"><div><div className="eyebrow"><span className="eyebrow-mark" /> CASE MANAGEMENT</div><h1>Keep the thread<br /><em>attached to evidence.</em></h1><p>Cases, relationships, indicators, notes, and activity are persisted by the backend. Exported reports contain only records attached to the selected case.</p></div><button className="button dark-button" onClick={() => void onRefresh()}><RefreshCw size={15} /> Refresh cases</button></section><section className="blacksite-two-column"><form className="mini-panel blacksite-panel blacksite-form-panel" onSubmit={save}><div className="eyebrow">{editingId ? 'EDIT CASE' : 'CREATE CASE'}</div><h2>{editingId ? 'Update investigation' : 'New investigation'}</h2><label className="blacksite-field"><span>Title *</span><input required value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} placeholder="Suspicious authentication activity" /></label><label className="blacksite-field"><span>Description</span><textarea value={draft.description} onChange={(event) => setDraft({ ...draft, description: event.target.value })} placeholder="Scope and current hypothesis" /></label><div className="blacksite-inline-fields"><label className="blacksite-field"><span>Indicators</span><textarea value={draft.indicators} onChange={(event) => setDraft({ ...draft, indicators: event.target.value })} placeholder="one IP, URL, hash, or domain per line" /></label><label className="blacksite-field"><span>Vulnerability IDs</span><textarea value={draft.vulnerabilityIds} onChange={(event) => setDraft({ ...draft, vulnerabilityIds: event.target.value })} placeholder="CVE-2024-1234" /></label></div><label className="blacksite-field"><span>Analyst notes</span><textarea value={draft.analystNotes} onChange={(event) => setDraft({ ...draft, analystNotes: event.target.value })} placeholder="Evidence-backed notes" /></label><div className="blacksite-inline-fields"><label className="blacksite-field"><span>Status</span><select value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value })}><option>open</option><option>investigating</option><option>awaiting_evidence</option><option>resolved</option><option>false_positive</option></select></label><label className="blacksite-field"><span>Priority</span><select value={draft.priority} onChange={(event) => setDraft({ ...draft, priority: event.target.value })}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label></div><label className="blacksite-field"><span>Assignee</span><input value={draft.assignee} onChange={(event) => setDraft({ ...draft, assignee: event.target.value })} placeholder="Operator or team" /></label><label className="blacksite-field"><span>Assets <small>Ctrl/Cmd-click for multiple</small></span><select multiple value={draft.assetIds.map(String)} onChange={(event) => setDraft({ ...draft, assetIds: selectedIds(event) })}>{assets.map((asset) => <option key={asset.id} value={asset.id}>#{asset.id} · {asset.name}</option>)}</select></label><label className="blacksite-field"><span>Events <small>Ctrl/Cmd-click for multiple</small></span><select multiple value={draft.eventIds.map(String)} onChange={(event) => setDraft({ ...draft, eventIds: selectedIds(event) })}>{events.map((item) => <option key={item.id} value={item.id}>#{item.id} · {item.event_type || item.type || 'event'}</option>)}</select></label><div className="blacksite-form-actions"><button className="button primary-button" type="submit" disabled={saving}>{saving ? <LoaderCircle size={15} className="spin" /> : editingId ? <Check size={15} /> : <Plus size={15} />} {editingId ? 'Save case' : 'Create case'}</button>{editingId && <button className="button secondary-button" type="button" onClick={() => { setEditingId(null); setDraft(emptyCaseDraft); }}>Cancel</button>}</div></form><div className="mini-panel blacksite-panel"><div className="mini-panel-heading"><div><div className="eyebrow">PERSISTED CASES</div><h2>{cases.length} case{cases.length === 1 ? '' : 's'}</h2></div><button className="icon-button" onClick={() => void onRefresh()} aria-label="Refresh cases"><RefreshCw size={16} /></button></div>{loading ? <LoadingState label="Loading cases…" /> : error ? <ErrorState message={error} onRetry={onRefresh} /> : cases.length === 0 ? <EmptyState title="No persisted cases" description="Create a case to associate assets, events, indicators, and exported reports." icon={FolderKanban} /> : <div className="blacksite-case-list">{cases.map((item) => <article className="blacksite-case-card" key={item.id}><div className="blacksite-rule-head"><div><strong>{item.title}</strong><span>#{item.id} · {item.assignee || 'unassigned'}</span></div><span className={`blacksite-pill ${statusClass(item.priority)}`}>{item.priority}</span></div><p>{item.description || 'No description recorded.'}</p><div className="blacksite-result-meta"><span>status <strong>{item.status}</strong></span><span>assets <strong>{item.asset_ids?.length || 0}</strong></span><span>events <strong>{item.event_ids?.length || 0}</strong></span><span>indicators <strong>{item.indicators?.length || item.related_indicators?.length || 0}</strong></span></div>{item.activities?.length ? <div className="blacksite-observations">{item.activities.slice(-3).map((activity) => <div key={activity.id}><span>{activity.action} · {formatDate(activity.created_at)}</span><p>{activity.detail}</p></div>)}</div> : null}<div className="blacksite-card-actions"><button className="text-button" onClick={() => edit(item)}><Pencil size={13} /> Edit</button><button className="text-button" onClick={() => onExport(item.id, 'json')}><Download size={13} /> JSON</button><button className="text-button" onClick={() => onExport(item.id, 'csv')}><Download size={13} /> CSV</button><button className="text-button" onClick={() => onExport(item.id, 'pdf')}><Download size={13} /> PDF</button><button className="icon-button danger-icon" onClick={() => void onDelete(item.id)} title="Delete case"><Trash2 size={14} /></button></div></article>)}</div>}</div></section></div>;
}

function CaseCard({ item, onEdit, onDelete, onExport }: { item: CaseRecord; onEdit: () => void; onDelete: () => void; onExport: (format: 'json' | 'csv' | 'pdf') => void }) {
  return <article className="blacksite-case-card"><div className="blacksite-rule-head"><div><strong>{item.title}</strong><span>#{item.id} · {item.assignee || 'unassigned'}</span></div><span className={`blacksite-pill ${statusClass(item.priority)}`}>{item.priority}</span></div><p>{item.description || 'No description recorded.'}</p><div className="blacksite-result-meta"><span>status <strong>{item.status}</strong></span><span>assets <strong>{item.asset_ids?.length || 0}</strong></span><span>events <strong>{item.event_ids?.length || 0}</strong></span><span>updated <strong>{formatDate(item.updated_at)}</strong></span></div><div className="blacksite-card-actions"><button className="text-button" onClick={onEdit}><Pencil size={13} /> Edit</button><button className="text-button" onClick={() => onExport('json')}><Download size={13} /> JSON</button><button className="text-button" onClick={() => onExport('csv')}><Download size={13} /> CSV</button><button className="text-button" onClick={() => onExport('pdf')}><Download size={13} /> PDF</button><button className="icon-button danger-icon" onClick={onDelete} title="Delete case"><Trash2 size={14} /></button></div></article>;
}

function ReportsView({ cases, loading, error, onRefresh, onExport }: { cases: CaseRecord[]; loading: boolean; error: string | null; onRefresh: () => Promise<void>; onExport: (id: number, format: 'json' | 'csv' | 'pdf') => Promise<void> }) {
  return <div className="view-stack"><section className="page-intro split-intro"><div><div className="eyebrow"><span className="eyebrow-mark" /> REPORT GENERATOR</div><h1>Export the evidence<br /><em>without inventing context.</em></h1><p>Reports are generated by the backend from persisted cases, linked assets, events, and analysis records. Missing evidence stays missing.</p></div><button className="button dark-button" onClick={() => void onRefresh()}><RefreshCw size={15} /> Refresh cases</button></section>{loading ? <LoadingState label="Loading reportable cases…" /> : error ? <ErrorState message={error} onRetry={onRefresh} /> : cases.length === 0 ? <EmptyState title="No reportable cases" description="Create a persisted case before exporting JSON, CSV, or PDF evidence." icon={BarChart3} action={<button className="button secondary-button" onClick={() => void onRefresh()}>Refresh records</button>} /> : <section className="blacksite-report-grid">{cases.map((item) => <article className="mini-panel blacksite-panel blacksite-report-card" key={item.id}><div className="blacksite-rule-head"><div><strong>CASE-{String(item.id).padStart(4, '0')}</strong><span>{item.title}</span></div><span className={`blacksite-pill ${statusClass(item.priority)}`}>{item.priority}</span></div><div className="blacksite-result-meta"><span>status <strong>{item.status}</strong></span><span>assets <strong>{item.asset_ids?.length || 0}</strong></span><span>events <strong>{item.event_ids?.length || 0}</strong></span><span>updated <strong>{formatDate(item.updated_at)}</strong></span></div><div className="blacksite-card-actions"><button className="text-button" onClick={() => void onExport(item.id, 'json')}><Download size={13} /> JSON</button><button className="text-button" onClick={() => void onExport(item.id, 'csv')}><Download size={13} /> CSV</button><button className="text-button" onClick={() => void onExport(item.id, 'pdf')}><Download size={13} /> PDF</button></div></article>)}</section>}</div>;
}

function AttackGraphLegacyView({ graph, loading, error, onRefresh }: { graph: GraphResult | null; loading: boolean; error: string | null; onRefresh: () => Promise<void> }) {
  return <div className="view-stack"><section className="page-intro split-intro"><div><div className="eyebrow"><span className="eyebrow-mark" /> ATTACK GRAPH</div><h1>Map only what<br /><em>the backend can connect.</em></h1><p>Nodes and edges are generated from persisted cases, assets, events, and analysis records. No synthetic graph is rendered.</p></div><button className="button dark-button" onClick={() => void onRefresh()}><RefreshCw size={15} /> Refresh graph</button></section>{loading ? <LoadingState label="Loading graph records…" /> : error ? <ErrorState message={error} onRetry={onRefresh} /> : !graph || graph.nodes.length === 0 ? <EmptyState title="No graph records" description="Create or import persisted records to give the graph a surface to map." icon={Network} /> : <><section className="stat-strip blacksite-stat-strip"><StatItem icon={<Network size={17} />} tone="indigo" label="NODES" value={String(graph.nodes.length)} detail={graph.source} /><StatItem icon={<GitBranch size={17} />} tone="mint" label="EDGES" value={String(graph.edges.length)} detail="deterministic relationships" /></section><section className="blacksite-graph-layout"><div className="mini-panel blacksite-panel"><div className="eyebrow">NODES</div><h2>Persisted entities</h2><div className="blacksite-node-grid">{graph.nodes.map((node) => <article className="blacksite-node-card" key={node.id}><div className={`blacksite-node-icon ${node.kind}`}><Network size={14} /></div><div><strong>{node.label}</strong><span>{node.kind} · {node.id}</span><small>{node.source}</small></div></article>)}</div></div><div className="mini-panel blacksite-panel"><div className="eyebrow">EDGES</div><h2>Evidence relationships</h2>{graph.edges.length === 0 ? <EmptyState title="No relationships" description="Nodes exist, but the backend returned no deterministic edges." icon={GitBranch} /> : <div className="blacksite-edge-list">{graph.edges.map((edge) => <div key={edge.id}><div><strong>{edge.relation}</strong><span>{edge.source} → {edge.target}</span></div><small>{edge.explanation} · {edge.source_attribution}</small></div>)}</div>}</div></section></>}</div>;
}

function AttackGraphView({ graph, loading, error, onRefresh }: { graph: GraphResult | null; loading: boolean; error: string | null; onRefresh: () => Promise<void> }) {
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [pathStart, setPathStart] = useState<string | null>(null);
  const [pathEnd, setPathEnd] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const visibleNodes = useMemo(() => (graph?.nodes || []).filter((node) => (kind === 'all' || node.kind === kind) && `${node.label} ${node.id} ${node.source}`.toLowerCase().includes(query.toLowerCase())), [graph, kind, query]);
  const visibleIds = new Set(visibleNodes.map((node) => node.id));
  const visibleEdges = (graph?.edges || []).filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target));
  const selected = (graph?.nodes || []).find((node) => node.id === selectedId) || null;
  const pathEdges = useMemo(() => {
    if (!pathStart || !pathEnd || !graph) return new Set<string>();
    const adjacency = new Map<string, Array<{ next: string; edge: GraphResult['edges'][number] }>>();
    graph.edges.forEach((edge) => { adjacency.set(edge.source, [...(adjacency.get(edge.source) || []), { next: edge.target, edge }]); adjacency.set(edge.target, [...(adjacency.get(edge.target) || []), { next: edge.source, edge }]); });
    const queue: string[] = [pathStart];
    const previous = new Map<string, { node: string; edge: GraphResult['edges'][number] }>();
    const visited = new Set([pathStart]);
    while (queue.length) { const current = queue.shift()!; if (current === pathEnd) break; for (const item of adjacency.get(current) || []) if (!visited.has(item.next)) { visited.add(item.next); previous.set(item.next, { node: current, edge: item.edge }); queue.push(item.next); } }
    const result = new Set<string>(); let current = pathEnd;
    while (current !== pathStart && previous.has(current)) { const step = previous.get(current)!; result.add(step.edge.id); current = step.node; }
    return result;
  }, [graph, pathStart, pathEnd]);

  const downloadGraph = () => {
    if (!graph) return;
    setExporting(true);
    const blob = new Blob([JSON.stringify({ ...graph, exported_at: new Date().toISOString(), filtered_node_ids: [...visibleIds] }, null, 2)], { type: 'application/json' });
     const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = 'aegis-graph.json'; document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url); setExporting(false);
  };

  return <div className="view-stack"><section className="page-intro split-intro"><div><div className="eyebrow"><span className="eyebrow-mark" /> ATTACK GRAPH</div><h1>Map only what<br /><em>the backend can connect.</em></h1><p>Relationships come from persisted records, analyst annotations, or deterministic indicator extraction. Search, filter, select, and trace a path without invented topology.</p></div><div className="blacksite-card-actions"><button className="button secondary-button" onClick={downloadGraph} disabled={!graph || exporting}><Download size={15} /> {exporting ? 'Exporting…' : 'Export JSON'}</button><button className="button dark-button" onClick={() => void onRefresh()}><RefreshCw size={15} /> Refresh graph</button></div></section>{loading ? <LoadingState label="Loading graph records…" /> : error ? <ErrorState message={error} onRetry={onRefresh} /> : !graph || graph.nodes.length === 0 ? <EmptyState title="No graph records" description="Create or import persisted records to give the graph a surface to map." icon={Network} /> : <><section className="filter-panel blacksite-filter-panel"><div className="filter-controls blacksite-filter-controls"><label className="search-field"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search nodes, IDs, or sources" /></label><select className="graph-filter-select" value={kind} onChange={(event) => setKind(event.target.value)}><option value="all">All entity types</option>{[...new Set(graph.nodes.map((node) => node.kind))].map((item) => <option key={item} value={item}>{item}</option>)}</select><button className="filter-button" onClick={() => { setQuery(''); setKind('all'); setSelectedId(null); setPathStart(null); setPathEnd(null); }}>Reset</button></div><div className="result-count"><strong>{visibleNodes.length}</strong> of {graph.nodes.length} nodes · <strong>{visibleEdges.length}</strong> visible relationships</div></section><section className="blacksite-graph-layout"><div className="mini-panel blacksite-panel"><div className="mini-panel-heading"><div><div className="eyebrow">ENTITY SURFACE</div><h2>Select a node</h2></div><span className="blacksite-source-chip"><Network size={13} /> {graph.source}</span></div><div className="blacksite-node-grid">{visibleNodes.map((node) => <button className={`blacksite-node-card ${selectedId === node.id ? 'selected' : ''}`} key={node.id} onClick={() => setSelectedId(node.id)}><div className={`blacksite-node-icon ${node.kind}`}><Network size={14} /></div><div><strong>{node.label}</strong><span>{node.kind} · {node.id}</span><small>{node.source}</small></div></button>)}</div>{visibleNodes.length === 0 && <EmptyState title="No matching nodes" description="Change the search or entity-type filter." icon={Search} />}</div><div className="mini-panel blacksite-panel"><div className="mini-panel-heading"><div><div className="eyebrow">EVIDENCE RELATIONSHIPS</div><h2>{visibleEdges.length} visible edge{visibleEdges.length === 1 ? '' : 's'}</h2></div></div><div className="blacksite-path-controls"><select value={pathStart || ''} onChange={(event) => setPathStart(event.target.value || null)}><option value="">Path start</option>{visibleNodes.map((node) => <option value={node.id} key={`start-${node.id}`}>{node.label}</option>)}</select><ArrowRight size={14} /><select value={pathEnd || ''} onChange={(event) => setPathEnd(event.target.value || null)}><option value="">Path end</option>{visibleNodes.map((node) => <option value={node.id} key={`end-${node.id}`}>{node.label}</option>)}</select></div>{visibleEdges.length === 0 ? <EmptyState title="No relationships in filter" description="Persisted nodes may not have a deterministic connection yet." icon={GitBranch} /> : <div className="blacksite-edge-list">{visibleEdges.map((edge) => <button className={`blacksite-edge-row ${pathEdges.has(edge.id) ? 'path-highlight' : ''}`} key={edge.id} onClick={() => { setSelectedId(edge.source); setPathStart(edge.source); setPathEnd(edge.target); }}><div><strong>{edge.relation}</strong><span>{edge.source} → {edge.target}</span></div><small>{edge.source_attribution}</small><p>{edge.explanation}</p></button>)}</div>}</div></section>{selected && <section className="mini-panel blacksite-panel blacksite-selected-node"><div className="eyebrow">SELECTED ENTITY</div><h2>{selected.label}</h2><div className="blacksite-result-meta"><span>kind <strong>{selected.kind}</strong></span><span>source <strong>{selected.source}</strong></span></div><p>{selected.explanation}</p><pre>{JSON.stringify(selected.data, null, 2)}</pre></section>}</>}</div>;
}

function LegacySettingsView({ health, loading, error, onRefresh }: { health: HealthResponse | null; loading: boolean; error: string | null; onRefresh: () => Promise<void> }) {
  return <div className="view-stack"><section className="page-intro"><div><div className="eyebrow"><span className="eyebrow-mark" /> SETTINGS</div><h1>Know the connection<br /><em>before you trust the screen.</em></h1><p>BLACKSITE reports backend health and database status here. The interface does not claim that any external integration is configured or available.</p></div></section><section className="blacksite-settings-grid"><div className="mini-panel blacksite-panel"><div className="mini-panel-heading"><div><div className="eyebrow">BACKEND HEALTH</div><h2>API service</h2></div><button className="icon-button" onClick={() => void onRefresh()} aria-label="Refresh backend health"><RefreshCw size={16} /></button></div>{loading ? <LoadingState label="Checking backend health…" /> : error ? <ErrorState message={error} onRetry={onRefresh} /> : health ? <div className="blacksite-health-list"><HealthRow label="status" value={health.status} tone={statusClass(health.status)} /><HealthRow label="database" value={health.database} tone={statusClass(health.database)} /><HealthRow label="service" value={health.service} /><HealthRow label="version" value={health.version} /><HealthRow label="API URL" value={API_BASE_URL} /></div> : <EmptyState title="No health response" description="Refresh to check the configured backend endpoint." icon={CloudOff} />}</div><div className="mini-panel blacksite-panel"><div className="eyebrow">OPERATING MODE</div><h2>Demo mode is explicit</h2><div className="blacksite-mode-callout"><Sparkles size={18} /><div><strong>DEMO MODE · REAL API DATA ONLY</strong><p>There are no seeded frontend findings. Empty states represent empty backend collections, and unavailable states represent failed requests.</p></div></div><div className="blacksite-settings-note"><Database size={15} /><span>Records are managed by the local BLACKSITE API and SQLite database.</span></div><div className="blacksite-settings-note"><Shield size={15} /><span>Intelligence responses display the source attribution returned by the backend.</span></div></div></section></div>;
}

function SettingsView({ health, loading, error, onRefresh }: { health: HealthResponse | null; loading: boolean; error: string | null; onRefresh: () => Promise<void> }) {
  return <div className="view-stack"><section className="page-intro"><div><div className="eyebrow"><span className="eyebrow-mark" /> SETTINGS</div><h1>Know the connection<br /><em>before you trust the screen.</em></h1><p>Aegis reports backend health and database status here. The interface does not claim that any external integration is configured or available.</p></div></section><section className="blacksite-settings-grid"><div className="mini-panel blacksite-panel"><div className="mini-panel-heading"><div><div className="eyebrow">BACKEND HEALTH</div><h2>API service</h2></div><button className="icon-button" onClick={() => void onRefresh()} aria-label="Refresh backend health"><RefreshCw size={16} /></button></div>{loading ? <LoadingState label="Checking backend health…" /> : error ? <ErrorState message={error} onRetry={onRefresh} /> : health ? <div className="blacksite-health-list"><HealthRow label="status" value={health.status} tone={statusClass(health.status)} /><HealthRow label="database" value={health.database} tone={statusClass(health.database)} /><HealthRow label="service" value={health.service} /><HealthRow label="version" value={health.version} /><HealthRow label="API URL" value={API_BASE_URL} /></div> : <EmptyState title="No health response" description="Refresh to check the configured backend endpoint." icon={CloudOff} />}</div><div className="mini-panel blacksite-panel"><div className="eyebrow">OPERATING MODE</div><h2>Aegis is local-first</h2><div className="blacksite-mode-callout"><Sparkles size={18} /><div><strong>DEMO MODE · REAL API DATA ONLY</strong><p>There are no seeded findings. Empty states represent empty backend collections, and unavailable states represent failed requests.</p></div></div><div className="blacksite-settings-note"><Database size={15} /><span>Records are managed by the local Aegis API and SQLite database.</span></div><div className="blacksite-settings-note"><Shield size={15} /><span>External intelligence providers are optional and source-attributed.</span></div></div></section></div>;
}

function HealthRow({ label, value, tone = 'neutral' }: { label: string; value: string; tone?: string }) {
  return <div className="blacksite-health-row"><span>{label}</span><strong className={tone === 'danger' ? 'danger-text' : tone === 'success' ? 'success-text' : ''}>{value}</strong></div>;
}

export default App;
