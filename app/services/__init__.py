"""
app/services package initialization.
Exposes public service workflows: embed_message, extract_message, estimate_capacity,
data models, and service exception classes.
"""

from app.services.cryptaudio_service import (
    CapacityEstimate,
    EmbedMessageResult,
    InsufficientAudioCapacityError,
    MessageEmbeddingError,
    MessageExtractionError,
    ServiceError,
    embed_message,
    estimate_capacity,
    extract_message,
)

__all__ = [
    "embed_message",
    "extract_message",
    "estimate_capacity",
    "EmbedMessageResult",
    "CapacityEstimate",
    "ServiceError",
    "MessageEmbeddingError",
    "MessageExtractionError",
    "InsufficientAudioCapacityError",
]
