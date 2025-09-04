"""
Collection Archive Service

Manages persistent storage for live ADB collections, organizing them for
historical lookup and case management.
"""

import os
import json
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import logging


@dataclass
class CollectionMetadata:
    """Metadata for a stored collection."""
    collection_id: str
    timestamp: str
    device_serial: str
    device_model: str
    device_manufacturer: str
    collection_profile: str
    android_version: str
    total_files: int
    total_size_mb: float
    analysis_duration_seconds: float
    risk_level: str
    overall_score: float
    storage_path: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class CollectionArchive:
    """
    Service for managing persistent storage of ADB collections.
    
    Creates organized archive structure:
    collections/
    ├── YYYY/
    │   ├── MM/
    │   │   ├── YYYYMMDD_HHMMSS_<device_model>/
    │   │   │   ├── raw_data/          # ADB collected files
    │   │   │   ├── analysis.log       # Complete analysis log
    │   │   │   ├── risk_assessment.json
    │   │   │   ├── collection_info.json
    │   │   │   └── metadata.json
    │   │   └── ...
    │   └── ...
    └── collections_index.json        # Master index of all collections
    """
    
    def __init__(self, archive_root: Optional[str] = None):
        """
        Initialize collection archive service.
        
        Args:
            archive_root: Root directory for collections (defaults to ./collections)
        """
        self.logger = logging.getLogger("collection.archive")
        
        # Set up archive root directory
        if archive_root:
            self.archive_root = Path(archive_root)
        else:
            # Default to collections directory in project root
            project_root = Path(__file__).parent.parent.parent
            self.archive_root = project_root / "collections"
        
        # Ensure archive directory exists
        self.archive_root.mkdir(parents=True, exist_ok=True)
        self.index_file = self.archive_root / "collections_index.json"
        
        # Load existing index
        self.index = self._load_index()
        
        self.logger.info(f"Collection archive initialized at: {self.archive_root}")
    
    def create_collection_directory(
        self, 
        device_serial: str, 
        device_model: str = "Unknown",
        device_manufacturer: str = "Unknown",
        collection_profile: str = "standard"
    ) -> str:
        """
        Create a new collection directory with proper organization.
        
        Args:
            device_serial: Device serial number
            device_model: Device model name
            device_manufacturer: Device manufacturer
            collection_profile: Collection profile used
            
        Returns:
            Path to created collection directory
        """
        now = datetime.now()
        
        # Create hierarchical directory structure: YYYY/MM/
        year_dir = self.archive_root / now.strftime("%Y")
        month_dir = year_dir / now.strftime("%m")
        
        # Create collection directory name
        safe_model = self._sanitize_filename(device_model)
        safe_serial = self._sanitize_filename(device_serial[-12:])  # Last 12 chars of serial
        collection_name = f"{now.strftime('%Y%m%d_%H%M%S')}_{safe_model}_{safe_serial}"
        collection_dir = month_dir / collection_name
        
        # Create directory structure
        collection_dir.mkdir(parents=True, exist_ok=True)
        (collection_dir / "raw_data").mkdir(exist_ok=True)
        
        # Create collection info file
        collection_info = {
            "collection_id": collection_name,
            "created": now.isoformat(),
            "device_serial": device_serial,
            "device_model": device_model,
            "device_manufacturer": device_manufacturer,
            "collection_profile": collection_profile,
            "status": "in_progress"
        }
        
        with open(collection_dir / "collection_info.json", 'w') as f:
            json.dump(collection_info, f, indent=2)
        
        self.logger.info(f"Created collection directory: {collection_dir}")
        return str(collection_dir)
    
    def finalize_collection(
        self,
        collection_path: str,
        analysis_result: Dict[str, Any],
        analysis_duration: float,
        device_info: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Finalize a collection by updating metadata and index.
        
        Args:
            collection_path: Path to collection directory
            analysis_result: Analysis results dictionary
            analysis_duration: Time taken for analysis in seconds
            device_info: Additional device information
            
        Returns:
            Collection ID for future reference
        """
        collection_dir = Path(collection_path)
        
        # Load collection info
        info_file = collection_dir / "collection_info.json"
        if info_file.exists():
            with open(info_file, 'r') as f:
                collection_info = json.load(f)
        else:
            collection_info = {}
        
        # Update with final information
        collection_info.update({
            "status": "completed",
            "completed": datetime.now().isoformat(),
            "analysis_duration_seconds": analysis_duration,
            "risk_level": analysis_result.get("risk_level", "unknown"),
            "overall_score": analysis_result.get("overall_score", 0.0),
            "total_detections": len(analysis_result.get("detections", [])),
            "heuristics_run": len(analysis_result.get("heuristic_results", {}))
        })
        
        if device_info:
            collection_info.update(device_info)
        
        # Calculate collection size
        total_size = self._calculate_directory_size(collection_dir)
        file_count = self._count_files_in_directory(collection_dir)
        
        collection_info.update({
            "total_files": file_count,
            "total_size_mb": round(total_size / (1024 * 1024), 2)
        })
        
        # Save updated collection info
        with open(info_file, 'w') as f:
            json.dump(collection_info, f, indent=2)
        
        # Create metadata object
        metadata = CollectionMetadata(
            collection_id=collection_info.get("collection_id", collection_dir.name),
            timestamp=collection_info.get("created", ""),
            device_serial=collection_info.get("device_serial", "unknown"),
            device_model=collection_info.get("device_model", "Unknown"),
            device_manufacturer=collection_info.get("device_manufacturer", "Unknown"),
            collection_profile=collection_info.get("collection_profile", "standard"),
            android_version=collection_info.get("android_version", "Unknown"),
            total_files=file_count,
            total_size_mb=round(total_size / (1024 * 1024), 2),
            analysis_duration_seconds=analysis_duration,
            risk_level=analysis_result.get("risk_level", "unknown"),
            overall_score=analysis_result.get("overall_score", 0.0),
            storage_path=str(collection_dir)
        )
        
        # Save metadata file
        with open(collection_dir / "metadata.json", 'w') as f:
            json.dump(metadata.to_dict(), f, indent=2)
        
        # Update master index
        self._update_index(metadata)
        
        self.logger.info(f"Finalized collection: {metadata.collection_id}")
        self.logger.info(f"  Files: {file_count}, Size: {metadata.total_size_mb} MB")
        self.logger.info(f"  Risk Level: {metadata.risk_level}, Score: {metadata.overall_score}")
        
        return metadata.collection_id
    
    def list_collections(
        self, 
        device_serial: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        risk_level: Optional[str] = None
    ) -> List[CollectionMetadata]:
        """
        List collections with optional filtering.
        
        Args:
            device_serial: Filter by device serial
            start_date: Filter by start date (YYYY-MM-DD)
            end_date: Filter by end date (YYYY-MM-DD)
            risk_level: Filter by risk level
            
        Returns:
            List of matching collection metadata
        """
        collections = []
        
        for collection_data in self.index.get("collections", []):
            metadata = CollectionMetadata(**collection_data)
            
            # Apply filters
            if device_serial and device_serial not in metadata.device_serial:
                continue
                
            if start_date or end_date:
                collection_date = metadata.timestamp[:10]  # YYYY-MM-DD
                if start_date and collection_date < start_date:
                    continue
                if end_date and collection_date > end_date:
                    continue
            
            if risk_level and metadata.risk_level.lower() != risk_level.lower():
                continue
            
            collections.append(metadata)
        
        # Sort by timestamp (newest first)
        collections.sort(key=lambda x: x.timestamp, reverse=True)
        return collections
    
    def get_collection(self, collection_id: str) -> Optional[CollectionMetadata]:
        """Get specific collection metadata by ID."""
        for collection_data in self.index.get("collections", []):
            if collection_data.get("collection_id") == collection_id:
                return CollectionMetadata(**collection_data)
        return None
    
    def delete_collection(self, collection_id: str) -> bool:
        """
        Delete a collection and remove from index.
        
        Args:
            collection_id: ID of collection to delete
            
        Returns:
            True if successful, False if not found
        """
        metadata = self.get_collection(collection_id)
        if not metadata:
            return False
        
        # Remove directory
        collection_path = Path(metadata.storage_path)
        if collection_path.exists():
            shutil.rmtree(collection_path)
            self.logger.info(f"Deleted collection directory: {collection_path}")
        
        # Remove from index
        self.index["collections"] = [
            c for c in self.index["collections"] 
            if c.get("collection_id") != collection_id
        ]
        self._save_index()
        
        self.logger.info(f"Deleted collection: {collection_id}")
        return True
    
    def get_archive_statistics(self) -> Dict[str, Any]:
        """Get statistics about the collection archive."""
        collections = self.index.get("collections", [])
        
        if not collections:
            return {
                "total_collections": 0,
                "total_size_mb": 0,
                "devices": [],
                "risk_levels": {},
                "date_range": None
            }
        
        # Calculate statistics
        total_size = sum(c.get("total_size_mb", 0) for c in collections)
        devices = list(set(c.get("device_serial", "") for c in collections))
        
        risk_counts = {}
        for collection in collections:
            risk = collection.get("risk_level", "unknown")
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        timestamps = [c.get("timestamp", "") for c in collections if c.get("timestamp")]
        date_range = None
        if timestamps:
            timestamps.sort()
            date_range = {
                "earliest": timestamps[0][:10],
                "latest": timestamps[-1][:10]
            }
        
        return {
            "total_collections": len(collections),
            "total_size_mb": round(total_size, 2),
            "unique_devices": len(devices),
            "devices": devices,
            "risk_level_counts": risk_counts,
            "date_range": date_range
        }
    
    def _load_index(self) -> Dict[str, Any]:
        """Load the collections index file."""
        if self.index_file.exists():
            try:
                with open(self.index_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                self.logger.warning(f"Could not load index file: {e}")
        
        # Create new index
        return {
            "version": "1.0",
            "created": datetime.now().isoformat(),
            "collections": []
        }
    
    def _save_index(self):
        """Save the collections index file."""
        self.index["last_updated"] = datetime.now().isoformat()
        try:
            with open(self.index_file, 'w') as f:
                json.dump(self.index, f, indent=2)
        except IOError as e:
            self.logger.error(f"Could not save index file: {e}")
    
    def _update_index(self, metadata: CollectionMetadata):
        """Update the master index with new collection."""
        # Remove existing entry if it exists
        self.index["collections"] = [
            c for c in self.index["collections"] 
            if c.get("collection_id") != metadata.collection_id
        ]
        
        # Add new entry
        self.index["collections"].append(metadata.to_dict())
        self._save_index()
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for cross-platform compatibility."""
        # Replace problematic characters
        safe_chars = []
        for char in filename:
            if char.isalnum() or char in '-_':
                safe_chars.append(char)
            else:
                safe_chars.append('_')
        
        return ''.join(safe_chars)[:50]  # Limit length
    
    def _calculate_directory_size(self, directory: Path) -> int:
        """Calculate total size of directory in bytes."""
        total_size = 0
        try:
            for file_path in directory.rglob('*'):
                if file_path.is_file():
                    total_size += file_path.stat().st_size
        except (OSError, IOError):
            pass
        return total_size
    
    def _count_files_in_directory(self, directory: Path) -> int:
        """Count total files in directory."""
        try:
            return len([f for f in directory.rglob('*') if f.is_file()])
        except (OSError, IOError):
            return 0
