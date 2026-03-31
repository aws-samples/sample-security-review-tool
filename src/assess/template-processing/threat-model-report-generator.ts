import { readFileSync } from 'fs';
import { getFriendlyDate } from '../../shared/utils/date-utils.js';

export interface Threat {
  id: string;
  stride_category: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  resource_type: string;
  resource_name: string;
  title: string;
  issue: string;
  attack_vector: string;
  impact: string;
  remediation: string;
  priority: number;
  estimated_effort: string;
  cwe_id?: string;
  compliance_violations?: string[];
  references?: string[];
}

interface ThreatSummary {
  total_threats: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  stride_breakdown: {
    spoofing: number;
    tampering: number;
    repudiation: number;
    information_disclosure: number;
    denial_of_service: number;
    elevation_of_privilege: number;
  };
}

interface PriorityAction {
  priority: number;
  action: string;
  threat_ids: string[];
  estimated_effort: string;
  business_justification: string;
}

export class ThreatReportGenerator {
  private template: string;

  constructor(templatePath?: string) {
    this.template = templatePath ?
      readFileSync(templatePath, 'utf8') :
      this.getDefaultTemplate();
  }

  public generateReport(
    threats: Threat[],
    templateName: string,
    analystName: string = 'Automated Analysis'
  ): string {
    const summary = this.calculateSummary(threats);
    const priorityActions = this.extractPriorityActions(threats);
    const complianceNotes = this.extractComplianceNotes(threats);

    const templateData = this.prepareTemplateData(
      threats,
      summary,
      priorityActions,
      complianceNotes,
      templateName,
      analystName
    );
    return this.renderTemplate(templateData);
  }

  private calculateSummary(threats: Threat[]): ThreatSummary {
    const summary: ThreatSummary = {
      total_threats: threats.length,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      stride_breakdown: {
        spoofing: 0,
        tampering: 0,
        repudiation: 0,
        information_disclosure: 0,
        denial_of_service: 0,
        elevation_of_privilege: 0
      }
    };

    threats.forEach(threat => {
      // Count by severity
      switch (threat.severity) {
        case 'Critical':
          summary.critical_count++;
          break;
        case 'High':
          summary.high_count++;
          break;
        case 'Medium':
          summary.medium_count++;
          break;
        case 'Low':
          summary.low_count++;
          break;
      }

      // Count by STRIDE category
      const categoryKey = threat.stride_category.toLowerCase().replace(/\s+/g, '_') as keyof typeof summary.stride_breakdown;
      if (summary.stride_breakdown[categoryKey] !== undefined) {
        summary.stride_breakdown[categoryKey]++;
      }
    });

    return summary;
  }

  private extractPriorityActions(threats: Threat[]): PriorityAction[] {
    // Sort threats by priority and take top items
    const prioritizedThreats = threats
      .filter(threat => threat.priority)
      .sort((a, b) => a.priority - b.priority)
      .slice(0, 10); // Top 10 priority actions

    return prioritizedThreats.map(threat => ({
      priority: threat.priority,
      action: threat.remediation,
      threat_ids: [threat.id],
      estimated_effort: threat.estimated_effort,
      business_justification: threat.impact
    }));
  }

  private extractComplianceNotes(threats: Threat[]): string[] {
    const complianceViolations = new Set<string>();

    threats.forEach(threat => {
      if (threat.compliance_violations) {
        threat.compliance_violations.forEach(violation => {
          complianceViolations.add(violation);
        });
      }
    });

    return Array.from(complianceViolations);
  }

  private prepareTemplateData(
    threats: Threat[],
    summary: ThreatSummary,
    priorityActions: PriorityAction[],
    complianceNotes: string[],
    templateName: string,
    analystName: string
  ) {
    // Calculate percentages
    const totalThreats = summary.total_threats || 1; // Avoid division by zero
    const criticalPercentage = Math.round((summary.critical_count / totalThreats) * 100);
    const highPercentage = Math.round((summary.high_count / totalThreats) * 100);
    const mediumPercentage = Math.round((summary.medium_count / totalThreats) * 100);
    const lowPercentage = Math.round((summary.low_count / totalThreats) * 100);

    // Group threats by severity
    const threatsBySeverity = this.groupThreatsBySeverity(threats);

    // Generate resource summary
    const resourceSummary = this.generateResourceSummary(threats);

    // Generate recommendations
    const recommendations = this.generateRecommendations(threats);

    // Extract template resources
    const templateResources = this.extractTemplateResources(threats);

    return {
      template_name: templateName,
      analysis_date: getFriendlyDate(new Date()),
      analyst_name: analystName,
      total_threats: summary.total_threats,
      critical_count: summary.critical_count,
      high_count: summary.high_count,
      medium_count: summary.medium_count,
      low_count: summary.low_count,
      critical_percentage: criticalPercentage,
      high_percentage: highPercentage,
      medium_percentage: mediumPercentage,
      low_percentage: lowPercentage,
      spoofing_count: summary.stride_breakdown.spoofing,
      tampering_count: summary.stride_breakdown.tampering,
      repudiation_count: summary.stride_breakdown.repudiation,
      information_disclosure_count: summary.stride_breakdown.information_disclosure,
      denial_of_service_count: summary.stride_breakdown.denial_of_service,
      elevation_of_privilege_count: summary.stride_breakdown.elevation_of_privilege,
      priority_actions: priorityActions.map(action => ({
        ...action,
        threat_ids: action.threat_ids.join(', ')
      })),
      threats_by_severity: threatsBySeverity,
      resource_summary: resourceSummary,
      compliance_notes: complianceNotes.length > 0 ? complianceNotes : null,
      immediate_recommendations: recommendations.immediate,
      hardening_recommendations: recommendations.hardening,
      best_practice_recommendations: recommendations.bestPractice,
      template_resources: templateResources
    };
  }

  private groupThreatsBySeverity(threats: Threat[]) {
    const severityOrder = ['Critical', 'High', 'Medium', 'Low'];
    const grouped = threats.reduce((acc, threat) => {
      if (!acc[threat.severity]) {
        acc[threat.severity] = [];
      }
      acc[threat.severity].push(threat);
      return acc;
    }, {} as Record<string, Threat[]>);

    return severityOrder
      .filter(severity => grouped[severity]?.length > 0)
      .map(severity => ({
        severity,
        threats: grouped[severity]
      }));
  }

  private generateResourceSummary(threats: Threat[]) {
    const resourceMap = new Map<string, {
      count: number;
      threats: Threat[];
    }>();

    threats.forEach(threat => {
      const key = threat.resource_type;
      if (!resourceMap.has(key)) {
        resourceMap.set(key, { count: 0, threats: [] });
      }
      resourceMap.get(key)!.threats.push(threat);
    });

    // Get unique resources by type
    const resourceCounts = new Map<string, Set<string>>();
    threats.forEach(threat => {
      if (!resourceCounts.has(threat.resource_type)) {
        resourceCounts.set(threat.resource_type, new Set());
      }
      resourceCounts.get(threat.resource_type)!.add(threat.resource_name);
    });

    return Array.from(resourceMap.entries()).map(([resourceType, data]) => {
      const uniqueResources = resourceCounts.get(resourceType)!;
      const severities = data.threats.map(t => t.severity);
      const maxSeverity = this.getHighestSeverity(severities);

      return {
        resource_type: resourceType,
        count: uniqueResources.size,
        threat_count: data.threats.length,
        max_severity: maxSeverity,
        resources: Array.from(uniqueResources).map(name => ({
          name,
          threat_count: data.threats.filter(t => t.resource_name === name).length,
          severity_breakdown: this.getSeverityBreakdown(
            data.threats.filter(t => t.resource_name === name)
          )
        }))
      };
    });
  }

  private generateRecommendations(threats: Threat[]) {
    const critical = threats.filter(t => t.severity === 'Critical');
    const high = threats.filter(t => t.severity === 'High');
    const medium = threats.filter(t => t.severity === 'Medium');
    const low = threats.filter(t => t.severity === 'Low');

    return {
      immediate: [...critical, ...high].map(t => t.remediation),
      hardening: medium.map(t => t.remediation),
      bestPractice: low.map(t => t.remediation)
    };
  }

  private extractTemplateResources(threats: Threat[]) {
    const resources = new Set<string>();
    threats.forEach(threat => {
      resources.add(`${threat.resource_name}|${threat.resource_type}`);
    });

    return Array.from(resources).map(resource => {
      const [logical_id, type] = resource.split('|');
      return { logical_id, type };
    });
  }

  private getHighestSeverity(severities: string[]): string {
    const severityOrder = ['Critical', 'High', 'Medium', 'Low'];
    for (const severity of severityOrder) {
      if (severities.includes(severity)) {
        return severity;
      }
    }
    return 'Low';
  }

  private getSeverityBreakdown(threats: Threat[]): string {
    const counts = threats.reduce((acc, t) => {
      acc[t.severity] = (acc[t.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return Object.entries(counts)
      .map(([severity, count]) => `${count} ${severity}`)
      .join(', ');
  }

  private renderTemplate(data: any): string {
    let result = this.template;

    // Simple template replacement - you might want to use a proper template engine like Handlebars
    Object.entries(data).forEach(([key, value]) => {
      const regex = new RegExp(`{{${key}}}`, 'g');
      result = result.replace(regex, String(value));
    });

    // Handle array iterations (simplified - you might want proper Handlebars for complex logic)
    result = this.renderArraySections(result, data);

    return result;
  }

  private renderArraySections(template: string, data: any): string {
    let result = template;

    // Handle priority_actions section
    if (data.priority_actions?.length > 0) {
      let actionsContent = '';
      data.priority_actions.forEach((action: any) => {
        actionsContent += `### ${action.priority}. ${action.action}\n\n`;
        actionsContent += `**Effort:** ${action.estimated_effort}  \n`;
        actionsContent += `**Related Threats:** ${action.threat_ids}  \n`;
        actionsContent += `**Business Impact:** ${action.business_justification}\n\n`;
      });
      result = result.replace(/{{#priority_actions}}[\s\S]*?{{\/priority_actions}}/g, actionsContent);
    }

    // Handle threats_by_severity section
    if (data.threats_by_severity?.length > 0) {
      let threatsContent = '';
      data.threats_by_severity.forEach((severityGroup: any) => {
        threatsContent += `## ${severityGroup.severity} Severity Threats\n\n`;
        severityGroup.threats.forEach((threat: any) => {
          threatsContent += `### ${threat.id}: ${threat.title}\n\n`;
          threatsContent += `**STRIDE Category:** ${threat.stride_category}  \n`;
          threatsContent += `**Affected Resource:** \`${threat.resource_name}\` (${threat.resource_type})  \n`;
          if (threat.cwe_id) {
            threatsContent += `**CWE ID:** ${threat.cwe_id}\n\n`;
          }
          threatsContent += `#### Issue\n${threat.issue}\n\n`;
          threatsContent += `#### Attack Vector\n${threat.attack_vector}\n\n`;
          threatsContent += `#### Potential Impact\n${threat.impact}\n\n`;
          threatsContent += `#### Remediation\n${threat.remediation}\n\n`;
          if (threat.references?.length > 0) {
            threatsContent += `**References:**\n`;
            threat.references.forEach((ref: string) => {
              threatsContent += `- ${ref}\n`;
            });
            threatsContent += '\n';
          }
          threatsContent += '---\n\n';
        });
      });
      result = result.replace(/{{#threats_by_severity}}[\s\S]*?{{\/threats_by_severity}}/g, threatsContent);
    }

    // Handle other array sections similarly...
    result = this.renderSimpleArrays(result, data);

    return result;
  }

  private renderSimpleArrays(template: string, data: any): string {
    let result = template;

    // Handle simple array rendering
    const arrayFields = [
      'immediate_recommendations',
      'hardening_recommendations',
      'best_practice_recommendations',
      'template_resources',
      'compliance_notes'
    ];

    arrayFields.forEach(field => {
      if (data[field]?.length > 0) {
        let content = '';
        data[field].forEach((item: any) => {
          if (typeof item === 'string') {
            content += `- ${item}\n`;
          } else if (item.logical_id && item.type) {
            content += `- **${item.logical_id}** (${item.type})\n`;
          }
        });
        const regex = new RegExp(`{{#${field}}}[\\s\\S]*?{{\\/${field}}}`, 'g');
        result = result.replace(regex, content);
      } else {
        // Remove empty sections
        const regex = new RegExp(`{{#${field}}}[\\s\\S]*?{{\\/${field}}}`, 'g');
        result = result.replace(regex, '');
      }
    });

    return result;
  }

  private getDefaultTemplate(): string {
    // Return the markdown template as a string
    return `# CloudFormation Threat Model Report

**Template:** \`{{template_name}}\`
**Analysis Date:** {{analysis_date}}
**Generated By:** CloudFormation Threat Modeling Tool

## Executive Summary

This threat model analysis identified **{{total_threats}}** security threats. The analysis reveals **{{critical_count}}** critical, **{{high_count}}** high, **{{medium_count}}** medium, and **{{low_count}}** low severity findings.

## Priority Actions

{{#priority_actions}}
### {{priority}}. {{action}}

**Effort:** {{estimated_effort}}
**Related Threats:** {{threat_ids}}
**Business Impact:** {{business_justification}}

{{/priority_actions}}

## Detailed Threat Analysis

{{#threats_by_severity}}
{{/threats_by_severity}}

---

*This report was generated automatically using STRIDE threat modeling methodology.*`;
  }
}
