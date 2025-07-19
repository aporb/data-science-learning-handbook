#!/usr/bin/env python3
"""
DoD Role Hierarchy Management System
Implements military rank-based and position-based role hierarchies with clearance levels
"""

import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta
import json


class MilitaryBranch(Enum):
    """Military service branches."""
    ARMY = "army"
    NAVY = "navy"
    AIR_FORCE = "air_force"
    MARINES = "marines"
    SPACE_FORCE = "space_force"
    COAST_GUARD = "coast_guard"
    CIVILIAN = "civilian"


class RankCategory(Enum):
    """Military rank categories."""
    ENLISTED = "enlisted"
    WARRANT_OFFICER = "warrant_officer"
    COMMISSIONED_OFFICER = "commissioned_officer"
    FLAG_OFFICER = "flag_officer"
    CIVILIAN = "civilian"


class ClearanceLevel(Enum):
    """DoD security clearance levels with numerical hierarchy."""
    UNCLASSIFIED = 0
    CONFIDENTIAL = 1
    SECRET = 2
    TOP_SECRET = 3
    TOP_SECRET_SCI = 4


class PositionType(Enum):
    """Position-based role types."""
    ANALYST = "analyst"
    ADMINISTRATOR = "administrator"
    SECURITY_OFFICER = "security_officer"
    COMMANDER = "commander"
    SUPERVISOR = "supervisor"
    SPECIALIST = "specialist"
    OPERATOR = "operator"


@dataclass
class MilitaryRank:
    """Military rank definition with hierarchy."""
    name: str
    abbreviation: str
    pay_grade: str
    branch: MilitaryBranch
    category: RankCategory
    hierarchy_level: int  # Lower number = higher rank
    authority_scope: List[str]
    
    def __str__(self):
        return f"{self.pay_grade} {self.name} ({self.branch.value})"


@dataclass
class Position:
    """Position-based role definition."""
    title: str
    position_type: PositionType
    required_clearance: ClearanceLevel
    authority_level: int  # 1=highest, 10=lowest
    responsibilities: List[str]
    reporting_structure: Optional[str] = None
    
    def __str__(self):
        return f"{self.title} ({self.position_type.value})"


@dataclass
class RoleAssignment:
    """User role assignment with temporal and contextual information."""
    user_id: str
    role_name: str
    role_type: str  # "rank", "position", "clearance", "custom"
    assigned_by: str
    assignment_date: datetime
    expiration_date: Optional[datetime] = None
    conditions: Dict[str, Any] = None
    active: bool = True
    
    def is_valid(self) -> bool:
        """Check if role assignment is currently valid."""
        if not self.active:
            return False
        
        if self.expiration_date and datetime.utcnow() > self.expiration_date:
            return False
        
        return True


class DoD_RankHierarchy:
    """DoD Military Rank Hierarchy definitions."""
    
    # Army Ranks
    ARMY_RANKS = [
        # Enlisted
        MilitaryRank("Private", "PVT", "E-1", MilitaryBranch.ARMY, RankCategory.ENLISTED, 100, ["basic_access"]),
        MilitaryRank("Private First Class", "PFC", "E-2", MilitaryBranch.ARMY, RankCategory.ENLISTED, 99, ["basic_access"]),
        MilitaryRank("Specialist", "SPC", "E-4", MilitaryBranch.ARMY, RankCategory.ENLISTED, 97, ["basic_access", "equipment_operator"]),
        MilitaryRank("Corporal", "CPL", "E-4", MilitaryBranch.ARMY, RankCategory.ENLISTED, 97, ["basic_access", "team_leader"]),
        MilitaryRank("Sergeant", "SGT", "E-5", MilitaryBranch.ARMY, RankCategory.ENLISTED, 95, ["team_leader", "training_nco"]),
        MilitaryRank("Staff Sergeant", "SSG", "E-6", MilitaryBranch.ARMY, RankCategory.ENLISTED, 94, ["squad_leader", "training_nco"]),
        MilitaryRank("Sergeant First Class", "SFC", "E-7", MilitaryBranch.ARMY, RankCategory.ENLISTED, 93, ["platoon_sergeant", "senior_nco"]),
        MilitaryRank("Master Sergeant", "MSG", "E-8", MilitaryBranch.ARMY, RankCategory.ENLISTED, 92, ["first_sergeant", "senior_nco"]),
        MilitaryRank("Sergeant Major", "SGM", "E-9", MilitaryBranch.ARMY, RankCategory.ENLISTED, 91, ["command_sergeant_major", "senior_nco"]),
        
        # Warrant Officers
        MilitaryRank("Warrant Officer 1", "WO1", "W-1", MilitaryBranch.ARMY, RankCategory.WARRANT_OFFICER, 80, ["technical_expert", "specialist_leader"]),
        MilitaryRank("Chief Warrant Officer 2", "CW2", "W-2", MilitaryBranch.ARMY, RankCategory.WARRANT_OFFICER, 79, ["technical_expert", "specialist_leader"]),
        MilitaryRank("Chief Warrant Officer 3", "CW3", "W-3", MilitaryBranch.ARMY, RankCategory.WARRANT_OFFICER, 78, ["senior_technical_expert", "specialist_leader"]),
        MilitaryRank("Chief Warrant Officer 4", "CW4", "W-4", MilitaryBranch.ARMY, RankCategory.WARRANT_OFFICER, 77, ["senior_technical_expert", "specialist_leader"]),
        MilitaryRank("Chief Warrant Officer 5", "CW5", "W-5", MilitaryBranch.ARMY, RankCategory.WARRANT_OFFICER, 76, ["senior_technical_expert", "specialist_leader"]),
        
        # Commissioned Officers
        MilitaryRank("Second Lieutenant", "2LT", "O-1", MilitaryBranch.ARMY, RankCategory.COMMISSIONED_OFFICER, 70, ["officer", "platoon_leader"]),
        MilitaryRank("First Lieutenant", "1LT", "O-2", MilitaryBranch.ARMY, RankCategory.COMMISSIONED_OFFICER, 69, ["officer", "platoon_leader"]),
        MilitaryRank("Captain", "CPT", "O-3", MilitaryBranch.ARMY, RankCategory.COMMISSIONED_OFFICER, 68, ["officer", "company_commander"]),
        MilitaryRank("Major", "MAJ", "O-4", MilitaryBranch.ARMY, RankCategory.COMMISSIONED_OFFICER, 67, ["field_grade_officer", "battalion_staff"]),
        MilitaryRank("Lieutenant Colonel", "LTC", "O-5", MilitaryBranch.ARMY, RankCategory.COMMISSIONED_OFFICER, 66, ["field_grade_officer", "battalion_commander"]),
        MilitaryRank("Colonel", "COL", "O-6", MilitaryBranch.ARMY, RankCategory.COMMISSIONED_OFFICER, 65, ["field_grade_officer", "brigade_commander"]),
        
        # General Officers
        MilitaryRank("Brigadier General", "BG", "O-7", MilitaryBranch.ARMY, RankCategory.FLAG_OFFICER, 60, ["general_officer", "strategic_command"]),
        MilitaryRank("Major General", "MG", "O-8", MilitaryBranch.ARMY, RankCategory.FLAG_OFFICER, 59, ["general_officer", "division_command"]),
        MilitaryRank("Lieutenant General", "LTG", "O-9", MilitaryBranch.ARMY, RankCategory.FLAG_OFFICER, 58, ["general_officer", "corps_command"]),
        MilitaryRank("General", "GEN", "O-10", MilitaryBranch.ARMY, RankCategory.FLAG_OFFICER, 57, ["general_officer", "army_command"]),
    ]
    
    # Navy Ranks (subset for example)
    NAVY_RANKS = [
        # Enlisted
        MilitaryRank("Seaman Recruit", "SR", "E-1", MilitaryBranch.NAVY, RankCategory.ENLISTED, 100, ["basic_access"]),
        MilitaryRank("Seaman Apprentice", "SA", "E-2", MilitaryBranch.NAVY, RankCategory.ENLISTED, 99, ["basic_access"]),
        MilitaryRank("Seaman", "SN", "E-3", MilitaryBranch.NAVY, RankCategory.ENLISTED, 98, ["basic_access"]),
        MilitaryRank("Petty Officer Third Class", "PO3", "E-4", MilitaryBranch.NAVY, RankCategory.ENLISTED, 97, ["petty_officer", "work_center_supervisor"]),
        MilitaryRank("Petty Officer Second Class", "PO2", "E-5", MilitaryBranch.NAVY, RankCategory.ENLISTED, 95, ["petty_officer", "division_supervisor"]),
        MilitaryRank("Petty Officer First Class", "PO1", "E-6", MilitaryBranch.NAVY, RankCategory.ENLISTED, 94, ["senior_petty_officer", "leading_petty_officer"]),
        MilitaryRank("Chief Petty Officer", "CPO", "E-7", MilitaryBranch.NAVY, RankCategory.ENLISTED, 93, ["chief_petty_officer", "department_chief"]),
        MilitaryRank("Senior Chief Petty Officer", "SCPO", "E-8", MilitaryBranch.NAVY, RankCategory.ENLISTED, 92, ["senior_chief", "command_master_chief"]),
        MilitaryRank("Master Chief Petty Officer", "MCPO", "E-9", MilitaryBranch.NAVY, RankCategory.ENLISTED, 91, ["master_chief", "fleet_master_chief"]),
        
        # Officers
        MilitaryRank("Ensign", "ENS", "O-1", MilitaryBranch.NAVY, RankCategory.COMMISSIONED_OFFICER, 70, ["officer", "division_officer"]),
        MilitaryRank("Lieutenant Junior Grade", "LTJG", "O-2", MilitaryBranch.NAVY, RankCategory.COMMISSIONED_OFFICER, 69, ["officer", "department_head"]),
        MilitaryRank("Lieutenant", "LT", "O-3", MilitaryBranch.NAVY, RankCategory.COMMISSIONED_OFFICER, 68, ["officer", "department_head"]),
        MilitaryRank("Lieutenant Commander", "LCDR", "O-4", MilitaryBranch.NAVY, RankCategory.COMMISSIONED_OFFICER, 67, ["field_grade_officer", "executive_officer"]),
        MilitaryRank("Commander", "CDR", "O-5", MilitaryBranch.NAVY, RankCategory.COMMISSIONED_OFFICER, 66, ["field_grade_officer", "commanding_officer"]),
        MilitaryRank("Captain", "CAPT", "O-6", MilitaryBranch.NAVY, RankCategory.COMMISSIONED_OFFICER, 65, ["field_grade_officer", "ship_captain"]),
        
        # Flag Officers
        MilitaryRank("Rear Admiral Lower Half", "RDML", "O-7", MilitaryBranch.NAVY, RankCategory.FLAG_OFFICER, 60, ["flag_officer", "task_force_commander"]),
        MilitaryRank("Rear Admiral", "RADM", "O-8", MilitaryBranch.NAVY, RankCategory.FLAG_OFFICER, 59, ["flag_officer", "fleet_commander"]),
        MilitaryRank("Vice Admiral", "VADM", "O-9", MilitaryBranch.NAVY, RankCategory.FLAG_OFFICER, 58, ["flag_officer", "fleet_commander"]),
        MilitaryRank("Admiral", "ADM", "O-10", MilitaryBranch.NAVY, RankCategory.FLAG_OFFICER, 57, ["flag_officer", "navy_command"]),
    ]
    
    # Civilian equivalent positions
    CIVILIAN_POSITIONS = [
        Position("Data Analyst", PositionType.ANALYST, ClearanceLevel.CONFIDENTIAL, 8, ["data_analysis", "reporting"]),
        Position("Senior Data Analyst", PositionType.ANALYST, ClearanceLevel.SECRET, 7, ["data_analysis", "reporting", "training"]),
        Position("Lead Data Scientist", PositionType.SPECIALIST, ClearanceLevel.SECRET, 6, ["advanced_analytics", "team_leadership"]),
        Position("System Administrator", PositionType.ADMINISTRATOR, ClearanceLevel.SECRET, 5, ["system_management", "user_access"]),
        Position("Senior System Administrator", PositionType.ADMINISTRATOR, ClearanceLevel.SECRET, 4, ["system_management", "security_administration"]),
        Position("Information System Security Officer", PositionType.SECURITY_OFFICER, ClearanceLevel.TOP_SECRET, 3, ["security_policy", "compliance", "incident_response"]),
        Position("Information System Security Manager", PositionType.SECURITY_OFFICER, ClearanceLevel.TOP_SECRET, 2, ["security_strategy", "policy_development", "risk_management"]),
        Position("Chief Information Officer", PositionType.ADMINISTRATOR, ClearanceLevel.TOP_SECRET, 1, ["strategic_planning", "executive_oversight", "budget_authority"]),
    ]

    @classmethod
    def get_all_ranks(cls) -> List[MilitaryRank]:
        """Get all military ranks across all branches."""
        return cls.ARMY_RANKS + cls.NAVY_RANKS
    
    @classmethod
    def get_ranks_by_branch(cls, branch: MilitaryBranch) -> List[MilitaryRank]:
        """Get ranks for a specific military branch."""
        all_ranks = cls.get_all_ranks()
        return [rank for rank in all_ranks if rank.branch == branch]
    
    @classmethod
    def get_rank_by_pay_grade(cls, pay_grade: str, branch: MilitaryBranch) -> Optional[MilitaryRank]:
        """Get rank by pay grade and branch."""
        ranks = cls.get_ranks_by_branch(branch)
        for rank in ranks:
            if rank.pay_grade == pay_grade:
                return rank
        return None


class RoleHierarchyManager:
    """
    Manages DoD role hierarchies including military ranks, civilian positions,
    and clearance-based access control.
    """
    
    def __init__(self):
        """Initialize the role hierarchy manager."""
        self.military_ranks = DoD_RankHierarchy.get_all_ranks()
        self.civilian_positions = DoD_RankHierarchy.CIVILIAN_POSITIONS
        self.role_assignments: Dict[str, List[RoleAssignment]] = {}
        self.role_inheritance_cache: Dict[str, Set[str]] = {}
        
        # Build rank lookup dictionaries
        self.rank_lookup = {
            f"{rank.pay_grade}_{rank.branch.value}": rank 
            for rank in self.military_ranks
        }
        
        self.position_lookup = {
            position.title.lower().replace(" ", "_"): position 
            for position in self.civilian_positions
        }
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def assign_military_rank(self, user_id: str, pay_grade: str, branch: MilitaryBranch,
                           assigned_by: str, expiration_date: Optional[datetime] = None) -> bool:
        """
        Assign military rank to a user.
        
        Args:
            user_id: User identifier
            pay_grade: Military pay grade (e.g., "E-5", "O-3")
            branch: Military branch
            assigned_by: Who assigned the rank
            expiration_date: When the assignment expires
            
        Returns:
            True if assignment successful
        """
        try:
            rank = DoD_RankHierarchy.get_rank_by_pay_grade(pay_grade, branch)
            if not rank:
                self.logger.error(f"Invalid rank: {pay_grade} for {branch.value}")
                return False
            
            assignment = RoleAssignment(
                user_id=user_id,
                role_name=f"{rank.pay_grade}_{rank.abbreviation}_{branch.value}",
                role_type="rank",
                assigned_by=assigned_by,
                assignment_date=datetime.utcnow(),
                expiration_date=expiration_date,
                conditions={"branch": branch.value, "pay_grade": pay_grade}
            )
            
            if user_id not in self.role_assignments:
                self.role_assignments[user_id] = []
            
            # Remove any existing rank assignments for this branch
            self.role_assignments[user_id] = [
                ra for ra in self.role_assignments[user_id] 
                if not (ra.role_type == "rank" and ra.conditions.get("branch") == branch.value)
            ]
            
            self.role_assignments[user_id].append(assignment)
            self._invalidate_cache(user_id)
            
            self.logger.info(f"Assigned rank {rank.name} to user {user_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to assign rank to {user_id}: {e}")
            return False
    
    def assign_position(self, user_id: str, position_title: str, assigned_by: str,
                       expiration_date: Optional[datetime] = None) -> bool:
        """
        Assign civilian position to a user.
        
        Args:
            user_id: User identifier
            position_title: Position title
            assigned_by: Who assigned the position
            expiration_date: When the assignment expires
            
        Returns:
            True if assignment successful
        """
        try:
            position_key = position_title.lower().replace(" ", "_")
            position = self.position_lookup.get(position_key)
            
            if not position:
                self.logger.error(f"Invalid position: {position_title}")
                return False
            
            assignment = RoleAssignment(
                user_id=user_id,
                role_name=position_key,
                role_type="position",
                assigned_by=assigned_by,
                assignment_date=datetime.utcnow(),
                expiration_date=expiration_date,
                conditions={"position_type": position.position_type.value}
            )
            
            if user_id not in self.role_assignments:
                self.role_assignments[user_id] = []
            
            self.role_assignments[user_id].append(assignment)
            self._invalidate_cache(user_id)
            
            self.logger.info(f"Assigned position {position.title} to user {user_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to assign position to {user_id}: {e}")
            return False
    
    def assign_clearance(self, user_id: str, clearance_level: ClearanceLevel,
                        assigned_by: str, expiration_date: Optional[datetime] = None,
                        compartments: List[str] = None) -> bool:
        """
        Assign security clearance to a user.
        
        Args:
            user_id: User identifier
            clearance_level: Security clearance level
            assigned_by: Who assigned the clearance
            expiration_date: When the clearance expires
            compartments: Additional clearance compartments (SCI, etc.)
            
        Returns:
            True if assignment successful
        """
        try:
            conditions = {
                "clearance_level": clearance_level.name,
                "compartments": compartments or []
            }
            
            assignment = RoleAssignment(
                user_id=user_id,
                role_name=f"clearance_{clearance_level.name.lower()}",
                role_type="clearance",
                assigned_by=assigned_by,
                assignment_date=datetime.utcnow(),
                expiration_date=expiration_date,
                conditions=conditions
            )
            
            if user_id not in self.role_assignments:
                self.role_assignments[user_id] = []
            
            # Remove any existing clearance assignments
            self.role_assignments[user_id] = [
                ra for ra in self.role_assignments[user_id] 
                if ra.role_type != "clearance"
            ]
            
            self.role_assignments[user_id].append(assignment)
            self._invalidate_cache(user_id)
            
            self.logger.info(f"Assigned {clearance_level.name} clearance to user {user_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to assign clearance to {user_id}: {e}")
            return False
    
    def get_user_roles(self, user_id: str, include_inherited: bool = True) -> List[str]:
        """
        Get all roles for a user, including inherited roles.
        
        Args:
            user_id: User identifier
            include_inherited: Whether to include inherited roles
            
        Returns:
            List of role names
        """
        if user_id not in self.role_assignments:
            return []
        
        # Get direct role assignments
        direct_roles = []
        for assignment in self.role_assignments[user_id]:
            if assignment.is_valid():
                direct_roles.append(assignment.role_name)
        
        if not include_inherited:
            return direct_roles
        
        # Get inherited roles
        inherited_roles = self._get_inherited_roles(user_id)
        
        # Combine and deduplicate
        all_roles = list(set(direct_roles + inherited_roles))
        return sorted(all_roles)
    
    def _get_inherited_roles(self, user_id: str) -> List[str]:
        """Get roles inherited through hierarchy."""
        if user_id in self.role_inheritance_cache:
            return list(self.role_inheritance_cache[user_id])
        
        inherited_roles = set()
        
        for assignment in self.role_assignments.get(user_id, []):
            if not assignment.is_valid():
                continue
            
            if assignment.role_type == "rank":
                # Get subordinate rank authorities
                branch = assignment.conditions.get("branch")
                pay_grade = assignment.conditions.get("pay_grade")
                
                if branch and pay_grade:
                    branch_enum = MilitaryBranch(branch)
                    current_rank = DoD_RankHierarchy.get_rank_by_pay_grade(pay_grade, branch_enum)
                    
                    if current_rank:
                        # Add authority-based roles
                        for authority in current_rank.authority_scope:
                            inherited_roles.add(f"authority_{authority}")
                        
                        # Add category-based roles
                        inherited_roles.add(f"category_{current_rank.category.value}")
                        
                        # Add hierarchy level roles (can command lower levels)
                        inherited_roles.add(f"hierarchy_level_{current_rank.hierarchy_level}")
            
            elif assignment.role_type == "position":
                # Get position-based authorities
                position_key = assignment.role_name
                position = self.position_lookup.get(position_key)
                
                if position:
                    # Add responsibility-based roles
                    for responsibility in position.responsibilities:
                        inherited_roles.add(f"responsibility_{responsibility}")
                    
                    # Add position type roles
                    inherited_roles.add(f"position_{position.position_type.value}")
                    
                    # Add authority level roles
                    inherited_roles.add(f"authority_level_{position.authority_level}")
            
            elif assignment.role_type == "clearance":
                # Add clearance-based roles
                clearance_level = assignment.conditions.get("clearance_level")
                if clearance_level:
                    inherited_roles.add(f"clearance_{clearance_level.lower()}")
                    
                    # Add access to lower classification levels
                    current_level = ClearanceLevel[clearance_level].value
                    for level in ClearanceLevel:
                        if level.value <= current_level:
                            inherited_roles.add(f"access_{level.name.lower()}")
                
                # Add compartment-based roles
                compartments = assignment.conditions.get("compartments", [])
                for compartment in compartments:
                    inherited_roles.add(f"compartment_{compartment.lower()}")
        
        # Cache results
        self.role_inheritance_cache[user_id] = inherited_roles
        
        return list(inherited_roles)
    
    def check_role_hierarchy(self, superior_user_id: str, subordinate_user_id: str) -> bool:
        """
        Check if one user outranks another in the hierarchy.
        
        Args:
            superior_user_id: Potential superior user
            subordinate_user_id: Potential subordinate user
            
        Returns:
            True if superior outranks subordinate
        """
        try:
            superior_level = self._get_user_hierarchy_level(superior_user_id)
            subordinate_level = self._get_user_hierarchy_level(subordinate_user_id)
            
            # Lower number = higher rank
            return superior_level < subordinate_level
            
        except Exception as e:
            self.logger.error(f"Error checking role hierarchy: {e}")
            return False
    
    def _get_user_hierarchy_level(self, user_id: str) -> int:
        """Get the highest hierarchy level for a user."""
        if user_id not in self.role_assignments:
            return 999  # Lowest possible level
        
        highest_level = 999
        
        for assignment in self.role_assignments[user_id]:
            if not assignment.is_valid():
                continue
            
            if assignment.role_type == "rank":
                branch = assignment.conditions.get("branch")
                pay_grade = assignment.conditions.get("pay_grade")
                
                if branch and pay_grade:
                    branch_enum = MilitaryBranch(branch)
                    rank = DoD_RankHierarchy.get_rank_by_pay_grade(pay_grade, branch_enum)
                    if rank:
                        highest_level = min(highest_level, rank.hierarchy_level)
            
            elif assignment.role_type == "position":
                position_key = assignment.role_name
                position = self.position_lookup.get(position_key)
                if position:
                    # Convert authority level to hierarchy level (lower authority = higher hierarchy)
                    hierarchy_level = position.authority_level + 50  # Offset to distinguish from military
                    highest_level = min(highest_level, hierarchy_level)
        
        return highest_level
    
    def get_user_clearance_level(self, user_id: str) -> Optional[ClearanceLevel]:
        """Get the highest clearance level for a user."""
        if user_id not in self.role_assignments:
            return None
        
        highest_clearance = None
        
        for assignment in self.role_assignments[user_id]:
            if assignment.is_valid() and assignment.role_type == "clearance":
                clearance_name = assignment.conditions.get("clearance_level")
                if clearance_name:
                    clearance_level = ClearanceLevel[clearance_name]
                    if highest_clearance is None or clearance_level.value > highest_clearance.value:
                        highest_clearance = clearance_level
        
        return highest_clearance
    
    def revoke_role(self, user_id: str, role_name: str, revoked_by: str) -> bool:
        """
        Revoke a specific role from a user.
        
        Args:
            user_id: User identifier
            role_name: Role to revoke
            revoked_by: Who revoked the role
            
        Returns:
            True if revocation successful
        """
        try:
            if user_id not in self.role_assignments:
                return False
            
            # Find and deactivate the role assignment
            for assignment in self.role_assignments[user_id]:
                if assignment.role_name == role_name and assignment.active:
                    assignment.active = False
                    assignment.conditions = assignment.conditions or {}
                    assignment.conditions["revoked_by"] = revoked_by
                    assignment.conditions["revoked_date"] = datetime.utcnow().isoformat()
                    
                    self._invalidate_cache(user_id)
                    self.logger.info(f"Revoked role {role_name} from user {user_id}")
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to revoke role {role_name} from {user_id}: {e}")
            return False
    
    def _invalidate_cache(self, user_id: str):
        """Invalidate cached role inheritance for a user."""
        if user_id in self.role_inheritance_cache:
            del self.role_inheritance_cache[user_id]
    
    def get_role_statistics(self) -> Dict[str, Any]:
        """Get statistics about role assignments."""
        stats = {
            "total_users": len(self.role_assignments),
            "total_assignments": 0,
            "active_assignments": 0,
            "by_role_type": {},
            "by_branch": {},
            "by_clearance": {}
        }
        
        for user_id, assignments in self.role_assignments.items():
            for assignment in assignments:
                stats["total_assignments"] += 1
                
                if assignment.is_valid():
                    stats["active_assignments"] += 1
                
                # Count by role type
                role_type = assignment.role_type
                stats["by_role_type"][role_type] = stats["by_role_type"].get(role_type, 0) + 1
                
                # Count by branch (for military ranks)
                if role_type == "rank":
                    branch = assignment.conditions.get("branch", "unknown")
                    stats["by_branch"][branch] = stats["by_branch"].get(branch, 0) + 1
                
                # Count by clearance level
                if role_type == "clearance":
                    clearance = assignment.conditions.get("clearance_level", "unknown")
                    stats["by_clearance"][clearance] = stats["by_clearance"].get(clearance, 0) + 1
        
        return stats
    
    def export_user_roles(self, user_id: str) -> Dict[str, Any]:
        """Export complete role information for a user."""
        if user_id not in self.role_assignments:
            return {"user_id": user_id, "roles": [], "inherited_roles": []}
        
        assignments = []
        for assignment in self.role_assignments[user_id]:
            assignments.append({
                "role_name": assignment.role_name,
                "role_type": assignment.role_type,
                "assigned_by": assignment.assigned_by,
                "assignment_date": assignment.assignment_date.isoformat(),
                "expiration_date": assignment.expiration_date.isoformat() if assignment.expiration_date else None,
                "active": assignment.active,
                "valid": assignment.is_valid(),
                "conditions": assignment.conditions
            })
        
        return {
            "user_id": user_id,
            "roles": assignments,
            "inherited_roles": self._get_inherited_roles(user_id),
            "hierarchy_level": self._get_user_hierarchy_level(user_id),
            "clearance_level": self.get_user_clearance_level(user_id).name if self.get_user_clearance_level(user_id) else None
        }


# Example usage
if __name__ == "__main__":
    # Initialize role hierarchy manager
    hierarchy_manager = RoleHierarchyManager()
    
    # Example user assignments
    test_user = "12345678-1234-1234-1234-123456789012"
    
    # Assign military rank
    hierarchy_manager.assign_military_rank(
        test_user, "E-6", MilitaryBranch.NAVY, "ADMIN_001"
    )
    
    # Assign security clearance
    hierarchy_manager.assign_clearance(
        test_user, ClearanceLevel.SECRET, "SECURITY_OFFICER_001"
    )
    
    # Assign civilian position
    hierarchy_manager.assign_position(
        test_user, "Senior Data Analyst", "SUPERVISOR_001"
    )
    
    # Get user roles
    roles = hierarchy_manager.get_user_roles(test_user)
    print(f"User roles: {roles}")
    
    # Export complete role information
    role_export = hierarchy_manager.export_user_roles(test_user)
    print(f"Complete role information: {json.dumps(role_export, indent=2)}")
    
    # Get system statistics
    stats = hierarchy_manager.get_role_statistics()
    print(f"Role statistics: {json.dumps(stats, indent=2)}")