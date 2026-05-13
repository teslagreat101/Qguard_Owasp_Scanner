"use client";

import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Eye, EyeOff, Download, Search, ChevronLeft, ChevronRight, Filter, Code } from "lucide-react";
import type { Finding } from "@/lib/api";

const SEVERITY_BADGE: Record<string, string> = {
    critical: "bg-red-500/15 text-red-500 border-red-500/30",
    high: "bg-orange-500/15 text-orange-500 border-orange-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-neon-green/10 text-neon-green border-neon-green/20",
    info: "bg-muted/10 text-muted-foreground border-border/20",
};

interface FindingsTableProps {
    findings: Finding[];
    totalFindings?: number;
    onExport?: () => void;
    onClear?: () => void;
}

export function FindingsTable({ findings, totalFindings, onExport, onClear }: FindingsTableProps) {
    const [revealedSecrets, setRevealedSecrets] = useState<Set<string>>(new Set());
    const [searchQuery, setSearchQuery] = useState("");
    const [severityFilter, setSeverityFilter] = useState("all");
    const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
    const [page, setPage] = useState(1);
    const pageSize = 25;

    const filteredFindings = useMemo(() => {
        let result = findings;
        if (severityFilter !== "all") {
            result = result.filter((f) => (f.severity || "").toLowerCase() === severityFilter);
        }
        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            result = result.filter((f) =>
                (f.title || "").toLowerCase().includes(q) || (f.file || "").toLowerCase().includes(q) || (f.cwe || "").toLowerCase().includes(q)
            );
        }
        return result;
    }, [findings, severityFilter, searchQuery]);

    const totalPages = Math.max(1, Math.ceil(filteredFindings.length / pageSize));
    const paginatedFindings = filteredFindings.slice((page - 1) * pageSize, page * pageSize);

    const toggleReveal = (id: string) => setRevealedSecrets((prev) => { const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s; });

    return (
        <Card className="bg-card border-border">
            <CardHeader>
                <div className="flex items-center justify-between flex-wrap gap-3">
                    <CardTitle className="text-foreground">Findings ({totalFindings ?? findings.length})</CardTitle>
                    <div className="flex items-center gap-2 flex-wrap">
                        <div className="relative"><Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                            <Input placeholder="Search..." value={searchQuery} onChange={(e) => { setSearchQuery(e.target.value); setPage(1); }}
                                className="pl-9 w-52 h-8 text-xs bg-deep border-border text-foreground" />
                        </div>
                        <Select value={severityFilter} onValueChange={(v) => { setSeverityFilter(v); setPage(1); }}>
                            <SelectTrigger className="w-32 h-8 text-xs bg-deep border-border text-foreground"><Filter className="h-3 w-3 mr-1" /><SelectValue /></SelectTrigger>
                            <SelectContent className="bg-card border-border">
                                <SelectItem value="all" className="text-foreground">All</SelectItem>
                                <SelectItem value="critical" className="text-red-500">Critical</SelectItem>
                                <SelectItem value="high" className="text-orange-500">High</SelectItem>
                                <SelectItem value="medium" className="text-yellow-400">Medium</SelectItem>
                                <SelectItem value="low" className="text-neon-green">Low</SelectItem>
                            </SelectContent>
                        </Select>
                        {onExport && <Button variant="outline" size="sm" onClick={onExport} className="h-8 text-xs border-border text-foreground"><Download className="h-3 w-3 mr-1" />Export</Button>}
                    </div>
                </div>
            </CardHeader>
            <CardContent>
                <ScrollArea className="h-[450px]">
                    <Table>
                        <TableHeader>
                            <TableRow className="border-border">
                                <TableHead className="text-muted-foreground w-24">Severity</TableHead>
                                <TableHead className="text-muted-foreground">Title</TableHead>
                                <TableHead className="text-muted-foreground w-48">Match</TableHead>
                                <TableHead className="text-muted-foreground">File</TableHead>
                                <TableHead className="text-muted-foreground w-20">CWE</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {paginatedFindings.length === 0 ? (
                                <TableRow><TableCell colSpan={5} className="text-center text-muted-foreground py-12">No findings match your filters.</TableCell></TableRow>
                            ) : (
                                paginatedFindings.map((f, i) => (
                                    <>
                                        <TableRow key={f.id || i} className="border-border hover:bg-deep cursor-pointer" onClick={() => setExpandedFinding(expandedFinding === (f.id || String(i)) ? null : (f.id || String(i)))}>
                                            <TableCell><Badge className={SEVERITY_BADGE[(f.severity || "info").toLowerCase()] || SEVERITY_BADGE.info}>{f.severity}</Badge></TableCell>
                                            <TableCell className="font-medium text-foreground text-sm max-w-xs truncate">{f.title}</TableCell>
                                            <TableCell>
                                                {f.matched_content ? (
                                                    <div className="flex items-center gap-1">
                                                        <code className="text-[10px] font-mono px-1.5 py-0.5 bg-deep rounded border border-border max-w-[140px] truncate block text-foreground">
                                                            {revealedSecrets.has(f.id || String(i)) ? f.matched_content : "•".repeat(Math.min(f.matched_content.length, 16))}
                                                        </code>
                                                        <Button variant="ghost" size="icon" className="h-5 w-5 text-neon-green" onClick={(e) => { e.stopPropagation(); toggleReveal(f.id || String(i)); }}>
                                                            {revealedSecrets.has(f.id || String(i)) ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                                                        </Button>
                                                    </div>
                                                ) : <span className="text-muted-foreground text-xs">—</span>}
                                            </TableCell>
                                            <TableCell className="font-mono text-[10px] text-neon-green max-w-[200px] truncate">{f.file}:{f.line_number}</TableCell>
                                            <TableCell className="text-muted-foreground text-xs">{f.cwe || "—"}</TableCell>
                                        </TableRow>
                                        {expandedFinding === (f.id || String(i)) && (
                                            <TableRow className="border-border">
                                                <TableCell colSpan={5} className="bg-deep/50 p-4">
                                                    <div className="grid grid-cols-2 gap-4 text-xs">
                                                        <div><span className="text-muted-foreground">Description:</span> <p className="text-foreground mt-1">{f.description || "—"}</p></div>
                                                        <div><span className="text-muted-foreground">Remediation:</span> <p className="text-foreground mt-1">{f.remediation || "—"}</p></div>
                                                        <div><span className="text-muted-foreground">Module:</span> <span className="text-foreground ml-1">{f.module_name || f.module}</span></div>
                                                        <div><span className="text-muted-foreground">OWASP:</span> <span className="text-neon-green ml-1">{f.owasp || "—"}</span></div>
                                                    </div>
                                                </TableCell>
                                            </TableRow>
                                        )}
                                    </>
                                ))
                            )}
                        </TableBody>
                    </Table>
                </ScrollArea>
                {/* Pagination */}
                {totalPages > 1 && (
                    <div className="flex items-center justify-between mt-3 pt-3 border-t border-border">
                        <span className="text-xs text-muted-foreground">Page {page} of {totalPages} ({filteredFindings.length} results)</span>
                        <div className="flex gap-1">
                            <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)} className="h-7 text-foreground"><ChevronLeft className="h-3.5 w-3.5" /></Button>
                            <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setPage(page + 1)} className="h-7 text-foreground"><ChevronRight className="h-3.5 w-3.5" /></Button>
                        </div>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}
