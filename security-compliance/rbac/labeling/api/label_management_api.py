"""
Label Management API

RESTful API for managing data labels with mandatory access control enforcement.
Provides endpoints for label creation, validation, querying, and lifecycle management.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-17
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from uuid import UUID, uuid4
from flask import Flask, request, jsonify, g
from flask_restful import Api, Resource, reqparse
from functools import wraps
import traceback

# Import models and engines
from ..models.label_models import (
    DataLabel, ClassificationLevel, NetworkDomain, ValidationStatus,
    InheritanceType, UserClearanceExtension, ClassificationAuthority,
    Compartment, Caveat, LabelAuditLog, AuditEventType, AccessDecision
)
from ..models.validation_models import (
    LabelValidator, ComplianceChecker, ValidationResult
)
from ..models.inheritance_models import (
    InheritanceManager, PropagationEngine, HierarchyManager
)
from ..engines.mac_enforcement_engine import (
    MACEnforcementEngine, AccessControlContext
)

# Import base models
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent / 'models'))
from base import DatabaseConnection

logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Should be from environment
api = Api(app)

# Initialize engines
db_connection = DatabaseConnection()
mac_engine = MACEnforcementEngine(db_connection)
validator = LabelValidator(db_connection)
compliance_checker = ComplianceChecker(db_connection)
inheritance_manager = InheritanceManager(db_connection)
propagation_engine = PropagationEngine(db_connection)
hierarchy_manager = HierarchyManager(db_connection)


def require_authentication(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # In production, this would validate JWT tokens, etc.
        # For now, we'll use a simple header
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            return {'error': 'Authentication required', 'message': 'X-User-ID header required'}, 401
        
        try:
            g.user_id = UUID(user_id)
        except ValueError:
            return {'error': 'Invalid user ID format'}, 400
        
        return f(*args, **kwargs)
    return decorated_function


def require_authorization(action: str):
    """Decorator to require authorization for specific actions."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if user has permission for this action
            # This would integrate with RBAC system
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def handle_api_error(f):
    """Decorator to handle API errors."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValueError as e:
            logger.error(f"Validation error in {f.__name__}: {e}")
            return {'error': 'Validation error', 'message': str(e)}, 400
        except PermissionError as e:
            logger.error(f"Permission error in {f.__name__}: {e}")
            return {'error': 'Permission denied', 'message': str(e)}, 403
        except Exception as e:
            logger.error(f"Internal error in {f.__name__}: {e}")
            logger.error(traceback.format_exc())
            return {'error': 'Internal server error', 'message': 'Please try again later'}, 500
    return decorated_function


class LabelResource(Resource):
    """Resource for managing individual labels."""
    
    method_decorators = [handle_api_error, require_authentication]
    
    def get(self, label_id: str):
        """Get label by ID."""
        try:
            label_uuid = UUID(label_id)
        except ValueError:
            return {'error': 'Invalid label ID format'}, 400
        
        # Check access
        decision_result = mac_engine.enforce_access(
            user_id=g.user_id,
            label_id=label_uuid,
            action='read'
        )
        
        if decision_result.decision != AccessDecision.PERMIT:
            return {
                'error': 'Access denied',
                'message': '; '.join(decision_result.reasons)
            }, 403
        
        # Get label
        label = DataLabel.find_by_id(label_uuid, db_connection)
        if not label:
            return {'error': 'Label not found'}, 404
        
        return self._label_to_dict(label)
    
    def put(self, label_id: str):
        """Update label."""
        try:
            label_uuid = UUID(label_id)
        except ValueError:
            return {'error': 'Invalid label ID format'}, 400
        
        # Check access
        decision_result = mac_engine.enforce_access(
            user_id=g.user_id,
            label_id=label_uuid,
            action='write'
        )
        
        if decision_result.decision != AccessDecision.PERMIT:
            return {
                'error': 'Access denied',
                'message': '; '.join(decision_result.reasons)
            }, 403
        
        # Get existing label
        label = DataLabel.find_by_id(label_uuid, db_connection)
        if not label:
            return {'error': 'Label not found'}, 404
        
        # Parse update data
        data = request.get_json()
        if not data:
            return {'error': 'No data provided'}, 400
        
        # Update label fields
        old_label_dict = label.to_dict()
        
        if 'classification_level' in data:
            label.classification_level = data['classification_level']
        
        if 'compartments' in data:
            label.compartments = [UUID(comp) for comp in data['compartments']]
        
        if 'caveats' in data:
            label.caveats = [UUID(cav) for cav in data['caveats']]
        
        if 'handling_instructions' in data:
            label.handling_instructions = data['handling_instructions']
        
        if 'declassification_date' in data:
            if data['declassification_date']:
                label.declassification_date = datetime.fromisoformat(data['declassification_date'])
            else:
                label.declassification_date = None
        
        # Validate updated label
        validation_result = validator.validate_label(label)
        if not validation_result.is_valid:
            return {
                'error': 'Validation failed',
                'validation_result': validation_result.to_dict()
            }, 400
        
        # Save changes
        label.save(g.user_id, db_connection)
        
        # Propagate changes if needed
        propagation_result = propagation_engine.propagate_changes(
            label.label_id,
            trigger=inheritance_manager.inheritance_rules['STANDARD_DOWNWARD'].propagation_triggers[0],
            user_id=g.user_id
        )
        
        return {
            'label': self._label_to_dict(label),
            'validation_result': validation_result.to_dict(),
            'propagation_result': propagation_result.to_dict()
        }
    
    def delete(self, label_id: str):
        """Delete label."""
        try:
            label_uuid = UUID(label_id)
        except ValueError:
            return {'error': 'Invalid label ID format'}, 400
        
        # Check access
        decision_result = mac_engine.enforce_access(
            user_id=g.user_id,
            label_id=label_uuid,
            action='delete'
        )
        
        if decision_result.decision != AccessDecision.PERMIT:
            return {
                'error': 'Access denied',
                'message': '; '.join(decision_result.reasons)
            }, 403
        
        # Get label
        label = DataLabel.find_by_id(label_uuid, db_connection)
        if not label:
            return {'error': 'Label not found'}, 404
        
        # Soft delete
        label.is_active = False
        label.save(g.user_id, db_connection)
        
        return {'message': 'Label deleted successfully'}
    
    def _label_to_dict(self, label: DataLabel) -> Dict[str, Any]:
        """Convert label to dictionary."""
        return {
            'label_id': str(label.label_id),
            'data_object_id': label.data_object_id,
            'data_object_type': label.data_object_type,
            'classification_level': label.classification_level,
            'compartments': [str(comp) for comp in label.compartments],
            'caveats': [str(cav) for cav in label.caveats],
            'network_domain': label.network_domain,
            'handling_instructions': label.handling_instructions,
            'dissemination_restrictions': label.dissemination_restrictions,
            'label_source': label.label_source,
            'parent_label_id': str(label.parent_label_id) if label.parent_label_id else None,
            'confidence_score': label.confidence_score,
            'validation_status': label.validation_status,
            'classification_date': label.classification_date.isoformat() if label.classification_date else None,
            'declassification_date': label.declassification_date.isoformat() if label.declassification_date else None,
            'control_markings': label.get_control_markings(),
            'is_active': label.is_active,
            'created_at': label.created_at.isoformat() if label.created_at else None,
            'modified_at': label.modified_at.isoformat() if label.modified_at else None,
            'label_metadata': label.label_metadata
        }


class LabelListResource(Resource):
    """Resource for managing label collections."""
    
    method_decorators = [handle_api_error, require_authentication]
    
    def get(self):
        """Get list of accessible labels."""
        parser = reqparse.RequestParser()
        parser.add_argument('classification_level', type=str, location='args')
        parser.add_argument('network_domain', type=str, location='args')
        parser.add_argument('data_object_type', type=str, location='args')
        parser.add_argument('validation_status', type=str, location='args')
        parser.add_argument('limit', type=int, default=100, location='args')
        parser.add_argument('offset', type=int, default=0, location='args')
        args = parser.parse_args()
        
        # Get accessible labels
        accessible_labels = mac_engine.get_accessible_labels(g.user_id, 'read', args['limit'] + args['offset'])
        
        # Apply filters
        filtered_labels = []
        for label in accessible_labels:
            if args['classification_level'] and label.classification_level != args['classification_level']:
                continue
            if args['network_domain'] and label.network_domain != args['network_domain']:
                continue
            if args['data_object_type'] and label.data_object_type != args['data_object_type']:
                continue
            if args['validation_status'] and label.validation_status != args['validation_status']:
                continue
            
            filtered_labels.append(label)
        
        # Apply pagination
        paginated_labels = filtered_labels[args['offset']:args['offset'] + args['limit']]
        
        return {
            'labels': [LabelResource()._label_to_dict(label) for label in paginated_labels],
            'total': len(filtered_labels),
            'offset': args['offset'],
            'limit': args['limit']
        }
    
    def post(self):
        """Create new label."""
        data = request.get_json()
        if not data:
            return {'error': 'No data provided'}, 400
        
        # Validate required fields
        required_fields = ['data_object_id', 'data_object_type', 'classification_level']
        for field in required_fields:
            if field not in data:
                return {'error': f'Missing required field: {field}'}, 400
        
        # Create label
        label = DataLabel(
            data_object_id=data['data_object_id'],
            data_object_type=data['data_object_type'],
            classification_level=data['classification_level'],
            network_domain=data.get('network_domain', 'NIPRNET'),
            compartments=[UUID(comp) for comp in data.get('compartments', [])],
            caveats=[UUID(cav) for cav in data.get('caveats', [])],
            handling_instructions=data.get('handling_instructions'),
            dissemination_restrictions=data.get('dissemination_restrictions'),
            label_source=data.get('label_source', 'EXPLICIT'),
            confidence_score=data.get('confidence_score'),
            classified_by=data.get('classified_by'),
            classification_date=datetime.now(timezone.utc),
            declassification_date=datetime.fromisoformat(data['declassification_date']) if data.get('declassification_date') else None,
            created_by=g.user_id,
            label_metadata=data.get('metadata', {})
        )
        
        # Validate label
        validation_result = validator.validate_label(label)
        if not validation_result.is_valid:
            return {
                'error': 'Validation failed',
                'validation_result': validation_result.to_dict()
            }, 400
        
        # Save label
        label.save(g.user_id, db_connection)
        
        return {
            'label': LabelResource()._label_to_dict(label),
            'validation_result': validation_result.to_dict()
        }, 201


class LabelValidationResource(Resource):
    """Resource for label validation."""
    
    method_decorators = [handle_api_error, require_authentication]
    
    def post(self, label_id: str):
        """Validate label."""
        try:
            label_uuid = UUID(label_id)
        except ValueError:
            return {'error': 'Invalid label ID format'}, 400
        
        # Get label
        label = DataLabel.find_by_id(label_uuid, db_connection)
        if not label:
            return {'error': 'Label not found'}, 404
        
        # Check access
        decision_result = mac_engine.enforce_access(
            user_id=g.user_id,
            label_id=label_uuid,
            action='read'
        )
        
        if decision_result.decision != AccessDecision.PERMIT:
            return {
                'error': 'Access denied',
                'message': '; '.join(decision_result.reasons)
            }, 403
        
        # Get validation parameters
        data = request.get_json() or {}
        rule_groups = data.get('rule_groups', ['all'])
        specific_rules = data.get('specific_rules')
        
        # Validate label
        validation_result = validator.validate_label(
            label,
            rule_groups=rule_groups,
            specific_rules=specific_rules
        )
        
        # Update label validation status
        if validation_result.is_valid:
            label.validation_status = ValidationStatus.VALIDATED.value
            label.validated_by = g.user_id
            label.validated_at = datetime.now(timezone.utc)
            label.save(g.user_id, db_connection)
        
        return validation_result.to_dict()


class LabelComplianceResource(Resource):
    """Resource for compliance checking."""
    
    method_decorators = [handle_api_error, require_authentication]
    
    def post(self, label_id: str):
        """Check compliance."""
        try:
            label_uuid = UUID(label_id)
        except ValueError:
            return {'error': 'Invalid label ID format'}, 400
        
        # Get label
        label = DataLabel.find_by_id(label_uuid, db_connection)
        if not label:
            return {'error': 'Label not found'}, 404
        
        # Check access
        decision_result = mac_engine.enforce_access(
            user_id=g.user_id,
            label_id=label_uuid,
            action='read'
        )
        
        if decision_result.decision != AccessDecision.PERMIT:
            return {
                'error': 'Access denied',
                'message': '; '.join(decision_result.reasons)
            }, 403
        
        # Check compliance
        compliance_result = compliance_checker.check_dod_compliance(label)
        
        return compliance_result.to_dict()


class LabelInheritanceResource(Resource):
    """Resource for label inheritance management."""
    
    method_decorators = [handle_api_error, require_authentication]
    
    def get(self, label_id: str):
        """Get label inheritance information."""
        try:
            label_uuid = UUID(label_id)
        except ValueError:
            return {'error': 'Invalid label ID format'}, 400
        
        # Get hierarchy information
        hierarchy_tree = hierarchy_manager.build_hierarchy_tree(label_uuid)
        inheritance_path = hierarchy_manager.get_inheritance_path(label_uuid)
        descendants = hierarchy_manager.get_descendants(label_uuid)
        ancestors = hierarchy_manager.get_ancestors(label_uuid)
        
        return {
            'hierarchy_tree': hierarchy_tree,
            'inheritance_path': [str(uuid) for uuid in inheritance_path],
            'descendants': [str(uuid) for uuid in descendants],
            'ancestors': [str(uuid) for uuid in ancestors],
            'hierarchy_depth': hierarchy_manager.calculate_hierarchy_depth(label_uuid)
        }
    
    def post(self, label_id: str):
        """Create inheritance relationship."""
        try:
            child_label_uuid = UUID(label_id)
        except ValueError:
            return {'error': 'Invalid label ID format'}, 400
        
        data = request.get_json()
        if not data or 'parent_label_id' not in data:
            return {'error': 'Parent label ID required'}, 400
        
        try:
            parent_label_uuid = UUID(data['parent_label_id'])
        except ValueError:
            return {'error': 'Invalid parent label ID format'}, 400
        
        # Create inheritance relationship
        inheritance_type = InheritanceType(data.get('inheritance_type', 'INHERITED'))
        
        inheritance = inheritance_manager.create_inheritance_relationship(
            parent_label_id=parent_label_uuid,
            child_label_id=child_label_uuid,
            inheritance_type=inheritance_type,
            user_id=g.user_id
        )
        
        return {
            'inheritance_id': str(inheritance.inheritance_id),
            'parent_label_id': str(inheritance.parent_label_id),
            'child_label_id': str(inheritance.child_label_id),
            'inheritance_type': inheritance.inheritance_type,
            'inheritance_depth': inheritance.inheritance_depth
        }


class LabelAccessResource(Resource):
    """Resource for checking label access."""
    
    method_decorators = [handle_api_error, require_authentication]
    
    def post(self, label_id: str):
        """Check access to label."""
        try:
            label_uuid = UUID(label_id)
        except ValueError:
            return {'error': 'Invalid label ID format'}, 400
        
        data = request.get_json()
        if not data or 'action' not in data:
            return {'error': 'Action required'}, 400
        
        # Check access
        decision_result = mac_engine.enforce_access(
            user_id=g.user_id,
            label_id=label_uuid,
            action=data['action'],
            context=AccessControlContext(data.get('context', 'NORMAL')),
            justification=data.get('justification'),
            emergency_override=data.get('emergency_override', False)
        )
        
        return decision_result.to_dict()


class LabelStatisticsResource(Resource):
    """Resource for label statistics."""
    
    method_decorators = [handle_api_error, require_authentication]
    
    def get(self):
        """Get label statistics."""
        # Get all accessible labels
        accessible_labels = mac_engine.get_accessible_labels(g.user_id, 'read', 10000)
        
        # Calculate statistics
        stats = {
            'total_labels': len(accessible_labels),
            'by_classification': {},
            'by_network_domain': {},
            'by_validation_status': {},
            'by_label_source': {}
        }
        
        for label in accessible_labels:
            # Classification distribution
            classification = label.classification_level
            stats['by_classification'][classification] = stats['by_classification'].get(classification, 0) + 1
            
            # Network domain distribution
            domain = label.network_domain
            stats['by_network_domain'][domain] = stats['by_network_domain'].get(domain, 0) + 1
            
            # Validation status distribution
            validation_status = label.validation_status
            stats['by_validation_status'][validation_status] = stats['by_validation_status'].get(validation_status, 0) + 1
            
            # Label source distribution
            source = label.label_source
            stats['by_label_source'][source] = stats['by_label_source'].get(source, 0) + 1
        
        return stats


# Register API resources
api.add_resource(LabelListResource, '/api/v1/labels')
api.add_resource(LabelResource, '/api/v1/labels/<string:label_id>')
api.add_resource(LabelValidationResource, '/api/v1/labels/<string:label_id>/validate')
api.add_resource(LabelComplianceResource, '/api/v1/labels/<string:label_id>/compliance')
api.add_resource(LabelInheritanceResource, '/api/v1/labels/<string:label_id>/inheritance')
api.add_resource(LabelAccessResource, '/api/v1/labels/<string:label_id>/access')
api.add_resource(LabelStatisticsResource, '/api/v1/labels/statistics')


# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '1.0.0'
    })


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)