import pytest
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer

Base = declarative_base()

class MockModel(Base):
    __tablename__ = "mock_table"
    id = Column(Integer, primary_key=True)

@pytest.fixture
def mock_model():
    return MockModel
