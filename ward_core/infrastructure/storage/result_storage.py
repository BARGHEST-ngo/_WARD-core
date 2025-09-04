"""
Result storage implementation.
"""

import json
from pathlib import Path
from typing import Dict, Any

from ward_core.logic.models import AnalysisResult


class ResultStorage:
    """
    Storage service for analysis results.
    """
    
    def __init__(self):
        """Initialize the storage service."""
        pass
    
    def save_result(self, result: AnalysisResult, output_path: str) -> None:
        """
        Save analysis result to file.
        
        Args:
            result: Analysis result to save
            output_path: Path to save the result
        """
        # Convert result to dictionary
        result_dict = result.to_dict()
        
        # Ensure directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Save as JSON
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=2, ensure_ascii=False)
    
    def load_result(self, input_path: str) -> Dict[str, Any]:
        """
        Load analysis result from file.
        
        Args:
            input_path: Path to load the result from
            
        Returns:
            Analysis result as dictionary
        """
        with open(input_path, 'r', encoding='utf-8') as f:
            return json.load(f)
