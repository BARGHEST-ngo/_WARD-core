"""
Episode Management Service - Centralized episode clustering and merging.

Consolidates all episode-related functionality from multiple heuristics and services
to eliminate redundancy and provide consistent episode management across the system.

This service replaces duplicate logic found in:
- memory_exploitation.py (_deduplicate_episodes, _merge_similar_episodes)
- scoring_service.py (consolidate_crash_detections)
- hybrid_collector.py (_merge_duplicate_sources)
- data_validator.py (_aggregate_issues)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, TypeVar, Generic, Callable
from collections import defaultdict
import logging

T = TypeVar('T')


@dataclass
class EpisodeConfig:
    """Configuration for episode clustering."""
    time_window_seconds: int = 60
    min_events_for_episode: int = 2
    max_time_gap_seconds: int = 300
    similarity_threshold: float = 0.7


class EpisodeItem(ABC):
    """Abstract base class for items that can be clustered into episodes."""
    
    @property
    @abstractmethod
    def timestamp(self) -> Optional[datetime]:
        """Get the timestamp of this item."""
        pass
    
    @property
    @abstractmethod
    def identifier(self) -> str:
        """Get a unique identifier for grouping similar items."""
        pass
    
    @abstractmethod
    def is_similar_to(self, other: 'EpisodeItem') -> bool:
        """Check if this item is similar to another for merging purposes."""
        pass


@dataclass
class Episode(Generic[T]):
    """Represents a clustered episode of related events."""
    start_time: datetime
    end_time: datetime
    items: List[T]
    episode_type: str
    confidence: float
    metadata: Dict[str, Any]
    
    @property
    def duration_seconds(self) -> float:
        """Get the duration of this episode in seconds."""
        return (self.end_time - self.start_time).total_seconds()
    
    @property
    def item_count(self) -> int:
        """Get the number of items in this episode."""
        return len(self.items)


class EpisodeService:
    """
    Centralized service for episode clustering, merging, and deduplication.
    
    This service provides consistent episode management functionality that was
    previously duplicated across multiple heuristics and services.
    """
    
    def __init__(self, config: Optional[EpisodeConfig] = None):
        """Initialize the episode service with configuration."""
        self.config = config or EpisodeConfig()
        self.logger = logging.getLogger("episode.service")
    
    def cluster_by_time(self, items: List[T], 
                       get_timestamp: Callable[[T], Optional[datetime]],
                       get_identifier: Callable[[T], str] = None,
                       episode_type: str = "temporal") -> List[Episode[T]]:
        """
        Cluster items into episodes based on temporal proximity.
        
        Args:
            items: List of items to cluster
            get_timestamp: Function to extract timestamp from item
            get_identifier: Optional function to extract identifier for grouping
            episode_type: Type of episode being created
            
        Returns:
            List of episodes
        """
        if not items:
            return []
        
        # Sort items by timestamp
        timestamped_items = [(item, get_timestamp(item)) for item in items]
        timestamped_items = [(item, ts) for item, ts in timestamped_items if ts is not None]
        timestamped_items.sort(key=lambda x: x[1])
        
        episodes = []
        current_episode_items = []
        current_start_time = None
        
        for item, timestamp in timestamped_items:
            if not current_episode_items:
                # Start new episode
                current_episode_items = [item]
                current_start_time = timestamp
            else:
                # Check if item belongs to current episode
                time_diff = (timestamp - current_start_time).total_seconds()
                
                if time_diff <= self.config.time_window_seconds:
                    current_episode_items.append(item)
                else:
                    # Finalize current episode if it meets criteria
                    if len(current_episode_items) >= self.config.min_events_for_episode:
                        episode = self._create_episode(
                            current_episode_items, episode_type, get_timestamp
                        )
                        episodes.append(episode)
                    
                    # Start new episode
                    current_episode_items = [item]
                    current_start_time = timestamp
        
        # Handle final episode
        if len(current_episode_items) >= self.config.min_events_for_episode:
            episode = self._create_episode(current_episode_items, episode_type, get_timestamp)
            episodes.append(episode)
        
        return episodes
    
    def merge_similar_episodes(self, episodes: List[Episode[T]], 
                             similarity_func: Callable[[Episode[T], Episode[T]], bool] = None) -> List[Episode[T]]:
        """
        Merge similar episodes that might be related.
        
        Args:
            episodes: List of episodes to merge
            similarity_func: Optional custom similarity function
            
        Returns:
            List of merged episodes
        """
        if len(episodes) <= 1:
            return episodes
        
        merged = []
        used_indices = set()
        
        for i, episode in enumerate(episodes):
            if i in used_indices:
                continue
            
            # Find similar episodes to merge
            similar_episodes = [episode]
            used_indices.add(i)
            
            for j, other_episode in enumerate(episodes[i+1:], i+1):
                if j in used_indices:
                    continue
                
                # Check similarity
                is_similar = False
                if similarity_func:
                    is_similar = similarity_func(episode, other_episode)
                else:
                    is_similar = self._are_episodes_similar(episode, other_episode)
                
                if is_similar:
                    similar_episodes.append(other_episode)
                    used_indices.add(j)
            
            # Merge similar episodes
            if len(similar_episodes) > 1:
                merged_episode = self._merge_episode_group(similar_episodes)
                merged.append(merged_episode)
            else:
                merged.append(episode)
        
        return merged
    
    def deduplicate_items(self, items: List[T], 
                         get_key: Callable[[T], str],
                         merge_func: Callable[[T, T], T] = None) -> List[T]:
        """
        Remove duplicate items and optionally merge them.
        
        Args:
            items: List of items to deduplicate
            get_key: Function to extract deduplication key
            merge_func: Optional function to merge duplicate items
            
        Returns:
            List of deduplicated items
        """
        if not items:
            return []
        
        item_groups = defaultdict(list)
        
        # Group items by key
        for item in items:
            key = get_key(item)
            item_groups[key].append(item)
        
        deduplicated = []
        
        for key, group in item_groups.items():
            if len(group) == 1:
                deduplicated.append(group[0])
            elif merge_func:
                # Merge duplicates
                merged_item = group[0]
                for item in group[1:]:
                    merged_item = merge_func(merged_item, item)
                deduplicated.append(merged_item)
            else:
                # Keep first item only
                deduplicated.append(group[0])
        
        return deduplicated
    
    def consolidate_by_root_cause(self, items: List[T],
                                get_root_cause: Callable[[T], str],
                                create_consolidated: Callable[[str, List[T]], T]) -> List[T]:
        """
        Consolidate items by root cause analysis.
        
        Args:
            items: List of items to consolidate
            get_root_cause: Function to extract root cause
            create_consolidated: Function to create consolidated item
            
        Returns:
            List of consolidated items
        """
        consolidated = []
        cause_groups = defaultdict(list)
        
        # Group items by root cause
        for item in items:
            root_cause = get_root_cause(item)
            cause_groups[root_cause].append(item)
        
        # Consolidate each group
        for root_cause, group in cause_groups.items():
            if len(group) > 1:
                consolidated_item = create_consolidated(root_cause, group)
                consolidated.append(consolidated_item)
            else:
                consolidated.extend(group)
        
        return consolidated
    
    def _create_episode(self, items: List[T], episode_type: str, 
                       get_timestamp: Callable[[T], Optional[datetime]]) -> Episode[T]:
        """Create an episode from a list of items."""
        timestamps = [get_timestamp(item) for item in items]
        valid_timestamps = [ts for ts in timestamps if ts is not None]
        
        if not valid_timestamps:
            # Fallback to current time
            start_time = end_time = datetime.now()
        else:
            start_time = min(valid_timestamps)
            end_time = max(valid_timestamps)
        
        # Calculate confidence based on item count and time clustering
        confidence = min(0.9, len(items) * 0.1 + 0.3)
        
        return Episode(
            start_time=start_time,
            end_time=end_time,
            items=items,
            episode_type=episode_type,
            confidence=confidence,
            metadata={
                'item_count': len(items),
                'duration_seconds': (end_time - start_time).total_seconds()
            }
        )
    
    def _are_episodes_similar(self, episode1: Episode[T], episode2: Episode[T]) -> bool:
        """Check if two episodes are similar enough to merge."""
        # Check time proximity
        time_gap = abs((episode1.start_time - episode2.start_time).total_seconds())
        if time_gap > self.config.max_time_gap_seconds:
            return False
        
        # Check episode type similarity
        if episode1.episode_type != episode2.episode_type:
            return False
        
        return True
    
    def _merge_episode_group(self, episodes: List[Episode[T]]) -> Episode[T]:
        """Merge a group of similar episodes into one."""
        # Sort by start time
        episodes.sort(key=lambda e: e.start_time)
        base_episode = episodes[0]
        
        # Merge all items
        all_items = []
        for episode in episodes:
            all_items.extend(episode.items)
        
        # Calculate merged time range
        start_time = min(e.start_time for e in episodes)
        end_time = max(e.end_time for e in episodes)
        
        # Merge metadata
        merged_metadata = base_episode.metadata.copy()
        merged_metadata.update({
            'merged_from': len(episodes),
            'original_episodes': [e.metadata.get('episode_id', id(e)) for e in episodes]
        })
        
        return Episode(
            start_time=start_time,
            end_time=end_time,
            items=all_items,
            episode_type=base_episode.episode_type,
            confidence=min(0.95, base_episode.confidence + 0.1 * (len(episodes) - 1)),
            metadata=merged_metadata
        )
