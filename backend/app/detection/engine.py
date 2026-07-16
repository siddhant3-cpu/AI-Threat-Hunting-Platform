import os
import yaml
import logging
import uuid
import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class SigmaEngine:
    def __init__(self, rules_dir: str = None):
        self.rules: List[Dict[str, Any]] = []
        if rules_dir and os.path.exists(rules_dir):
            self.load_rules_from_dir(rules_dir)

    def load_rules_from_dir(self, rules_dir: str):
        for root, _, files in os.walk(rules_dir):
            for file in files:
                if file.endswith(('.yml', '.yaml')):
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            rule_data = yaml.safe_load(f)
                            if rule_data and isinstance(rule_data, dict):
                                self.rules.append(rule_data)
                    except Exception as e:
                        logger.error(f"Error loading rule {path}: {e}")
        logger.info(f"Loaded {len(self.rules)} Sigma rules from disk.")

    def add_rule(self, rule_yaml: str) -> bool:
        try:
            rule_data = yaml.safe_load(rule_yaml)
            if rule_data and isinstance(rule_data, dict):
                # Remove if exists already
                self.rules = [r for r in self.rules if r.get('id') != rule_data.get('id')]
                self.rules.append(rule_data)
                return True
        except Exception as e:
            logger.error(f"Failed to add dynamic rule: {e}")
        return False

    def remove_rule(self, rule_id: str):
        self.rules = [r for r in self.rules if r.get('id') != rule_id]

    def _match_value(self, actual: Any, expected: Any, modifier: str = None) -> bool:
        if actual is None:
            return False
        
        actual_str = str(actual).lower()
        
        # Helper to convert expected to lists
        expected_list = expected if isinstance(expected, list) else [expected]
        expected_list = [str(e).lower() for e in expected_list]
        
        for exp in expected_list:
            if modifier == 'contains':
                if exp in actual_str:
                    return True
            elif modifier == 'endswith':
                if actual_str.endswith(exp):
                    return True
            elif modifier == 'startswith':
                if actual_str.startswith(exp):
                    return True
            else:
                # Exact match
                if actual_str == exp:
                    return True
        return False

    def _evaluate_selection(self, selection_dict: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """
        Evaluate a single selection block. All fields specified in the block must match (AND relationship).
        """
        for field_expr, expected_val in selection_dict.items():
            # Check if field has modifier (e.g. Image|endswith)
            if '|' in field_expr:
                field_name, modifier = field_expr.split('|', 1)
            else:
                field_name, modifier = field_expr, None
                
            # Resolve actual value from event, checking root fields first, then fields sub-dict (case-insensitive)
            actual_val = None
            field_name_lower = field_name.lower()
            
            def lookup(d):
                if not isinstance(d, dict):
                    return None
                for k, v in d.items():
                    if k.lower() == field_name_lower:
                        return v
                # Special mapping: EventID <-> event_id
                if field_name_lower == "eventid":
                    for k, v in d.items():
                        if k.lower() == "event_id":
                            return v
                return None

            actual_val = lookup(event)
            if actual_val is None and 'fields' in event and isinstance(event['fields'], dict):
                actual_val = lookup(event['fields'])
                
            if not self._match_value(actual_val, expected_val, modifier):
                return False
        return True

    def evaluate_rule(self, rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """
        Evaluate a Sigma rule against a raw log event.
        """
        # Basic logsource validation (if present)
        # For simplicity, we match category or service, or product.
        logsource = rule.get('logsource', {})
        category = logsource.get('category')
        service = logsource.get('service')
        
        event_source = event.get('source', '')
        # Check simple log source applicability
        if category and category.lower() not in event_source.lower():
            # If the log source category is specified but doesn't align with the event source name, skip
            # Unless category is authentication and source is ssh/auth
            if not (category.lower() == 'authentication' and ('auth' in event_source.lower() or 'ssh' in event_source.lower() or 'log' in event_source.lower())):
                return False

        detection = rule.get('detection', {})
        if not detection:
            return False

        condition = detection.get('condition', '')
        if not condition:
            return False

        # Gather selections
        selections = {k: v for k, v in detection.items() if k != 'condition'}
        selections_results = {}
        
        for sel_name, sel_dict in selections.items():
            # Sometimes selections are lists of dicts (OR condition inside selection)
            if isinstance(sel_dict, list):
                selections_results[sel_name] = any(
                    self._evaluate_selection(sub_dict, event) for sub_dict in sel_dict if isinstance(sub_dict, dict)
                )
            elif isinstance(sel_dict, dict):
                selections_results[sel_name] = self._evaluate_selection(sel_dict, event)
            else:
                selections_results[sel_name] = False

        # Evaluate condition expression e.g. "selection" or "selection_cmd or selection_image"
        # We will support standard conditional checks via python eval for educational purposes
        # Replacing rule selection names with their boolean outcomes
        try:
            expr = condition.lower()
            # Sort keys by length descending to prevent replacing substrings incorrectly
            for sel_name in sorted(selections_results.keys(), key=len, reverse=True):
                expr = expr.replace(sel_name.lower(), str(selections_results[sel_name]))
            
            # Sanitize expression
            expr = expr.replace('and', ' and ').replace('or', ' or ').replace('not', ' not ')
            # Safe evaluation
            allowed_names = {'True': True, 'False': False, 'and': None, 'or': None, 'not': None}
            # Simple eval
            return eval(expr, {"__builtins__": None}, allowed_names)
        except Exception as e:
            logger.error(f"Error evaluating condition '{condition}' for rule '{rule.get('title')}': {e}")
            return False

    def run_rules(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze a log event against all active Sigma rules.
        Returns a list of created Alerts.
        """
        triggered_alerts = []
        for rule in self.rules:
            if rule.get('status') == 'inactive':
                continue
            if self.evaluate_rule(rule, event):
                # Extract MITRE ATT&CK techniques from tags
                mitre_techniques = []
                tags = rule.get('tags', [])
                if isinstance(tags, list):
                    for tag in tags:
                        if tag.startswith('attack.t'):
                            mitre_techniques.append(tag.replace('attack.', '').upper())
                        elif tag.startswith('attack.') and len(tag) > 7:
                            # E.g. attack.persistence
                            mitre_techniques.append(tag.replace('attack.', '').capitalize())

                alert = {
                    "id": str(uuid.uuid4()),
                    "rule_id": rule.get('id', 'unknown'),
                    "rule_name": rule.get('title', 'Unknown Rule'),
                    "severity": rule.get('severity', 'Low').capitalize(),
                    "description": rule.get('description', ''),
                    "host": event.get('host'),
                    "user": event.get('user'),
                    "log_source": event.get('source'),
                    "mitre_techniques": mitre_techniques,
                    "details": event,
                    "timestamp": event.get('timestamp', datetime.datetime.utcnow())
                }
                triggered_alerts.append(alert)
        return triggered_alerts
