# SystemGuardian Service Documentation

## Overview
SystemGuardian is an advanced Windows service that provides automated system monitoring, protection, and recovery capabilities. It implements real-time component tracking, automatic recovery points, and intelligent event handling to maintain system stability and integrity.

## Key Features
- Real-time WMI-based event monitoring
- Automated recovery point management
- Registry state tracking and backup
- Component integrity verification
- Intelligent thread pool management
- SQLite-based component and event tracking
- Automated system restoration capabilities
- Smart component isolation and quarantine

## System Requirements

### Hardware Requirements
- Windows Operating System (Windows 10/11 recommended)
- Minimum 4GB RAM
- 1GB free disk space for recovery points

### Software Prerequisites
- Python 3.8 or higher
- Required Python packages:
```
win32serviceutil
wmi
psutil
win10toast
sqlite3
```

## Directory Structure
```
C:/ProgramData/SystemGuardian/
├── logs/                     # Rotating log files
├── backups/                  # Registry and component backups
├── recovery_points/          # System recovery points
├── quarantine/               # Isolated components
└── guardian.db               # SQLite database
```

## Database Schema

### Components Table
```sql
CREATE TABLE components (
    name TEXT PRIMARY KEY,
    type TEXT,
    path TEXT,
    dependencies TEXT,
    hash TEXT,
    last_modified REAL,
    status TEXT
);
```

### Recovery Points Table
```sql
CREATE TABLE recovery_points (
    timestamp REAL PRIMARY KEY,
    components TEXT,
    registry_backup TEXT,
    description TEXT
);
```

### Events Table
```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    timestamp REAL,
    type TEXT,
    component TEXT,
    description TEXT,
    severity TEXT
);
```

## Service Installation

### Basic Installation
```bash
python SystemGuardian.py install
```

### Service Management
- Start service
```bash
python SystemGuardian.py start
```
- Stop service
```bash
python SystemGuardian.py stop
```
- Update service
```bash
python SystemGuardian.py update
```
- Remove service
```bash
python SystemGuardian.py remove
```
## Recovery System

### Recovery Points
- Automatic creation before critical operations
- Maximum retention: 5 recovery points
- Includes:
  - Full registry state
  - Component database snapshot
  - System state metadata

### Recovery Point Creation
Recovery points are automatically created:
- At service startup
- Before critical component modifications
- Before component isolation
- During service shutdown
- On-demand via API

### Recovery Point Restoration
```python
# Example restoration code
guardian_service.restore_recovery_point(timestamp)
```

## Monitoring System

### WMI Event Monitoring
- Real-time event capture
- Efficient event filtering
- Resource-aware processing
- Automated response triggers

### Component Integrity
- SHA-256 hash verification
- Dependency validation
- Path existence checking
- Permission verification

## Thread Management

### Thread Pool
- Maximum workers: 4
- Automatic task distribution
- Resource-aware scheduling
- Graceful shutdown handling

### Event Queue
- Maximum size: 1000 events
- FIFO processing
- Overflow protection
- Priority handling

## Configuration

### Service Configuration
```python
class Config:
    MAX_QUEUE_SIZE = 1000
    MAX_THREADS = 4
    MAX_RECOVERY_POINTS = 5
    MAX_BACKUP_AGE_DAYS = 7
    EVENT_CHECK_INTERVAL = 5
    CACHE_UPDATE_INTERVAL = 3600
    BACKUP_INTERVAL = 86400
```

### Registry Monitoring
Monitored paths:
```python
CRITICAL_REG_PATHS = [
    r"SYSTEM\CurrentControlSet\Services",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32",
    r"SYSTEM\CurrentControlSet\Control\Class"
]
```

## Component Management

### Component States
- Active: Component running normally
- Warning: Minor issues detected
- Critical: Major problems identified
- Isolated: Component quarantined
- Recovered: Restored from backup

### Isolation Process
1. Create recovery point
2. Backup component files
3. Disable/stop component
4. Update database status
5. Notify administrator

### Recovery Process
1. Verify recovery point integrity
2. Restore registry state
3. Restore component files
4. Validate restoration
5. Update component status

## Logging System

### Log Rotation
- Daily log files
- Maximum size: 10MB
- Retention: 5 files
- Format: `guardian_YYYYMMDD.log`

### Log Levels
- INFO: Normal operations
- WARNING: Potential issues
- ERROR: Operation failures
- CRITICAL: System failures

## Performance Considerations

### Resource Usage
- CPU: <5% average
- Memory: ~100MB baseline
- Disk: ~1GB for recovery points
- Database: ~50MB typical

### Optimization
- Event batching
- Efficient WMI queries
- Thread pool management
- Queue size limits

## Security Features

### Component Verification
- File hash validation
- Path verification
- Permission checking
- Dependency validation

### Backup Security
- Encrypted storage
- Access control
- Integrity verification
- Secure deletion

## Troubleshooting

### Common Issues
1. Service Start Failure
   - Check database permissions
   - Verify directory access
   - Review WMI permissions
   - Check log files

2. Recovery Point Creation Failure
   - Verify disk space
   - Check backup directory permissions
   - Review database connectivity
   - Check registry access

3. Component Isolation Issues
   - Verify administrative rights
   - Check component dependencies
   - Review isolation logs
   - Verify backup creation

### Diagnostic Steps
1. Check service status
```powershell
Get-Service SystemGuardian | Format-List *
```

2. Review recent logs
```powershell
Get-Content "C:\ProgramData\SystemGuardian\logs\guardian_*.log" -Tail 100
```

3. Check recovery points
```sql
SELECT * FROM recovery_points ORDER BY timestamp DESC LIMIT 5;
```

4. Verify component status
```sql
SELECT name, status FROM components WHERE status != 'Active';
```

## Best Practices

### Maintenance
1. Regular database cleanup
2. Log rotation verification
3. Recovery point validation
4. Component status review

### Monitoring
1. Regular log review
2. Performance tracking
3. Resource usage monitoring
4. Event pattern analysis

### Backup Strategy
1. Regular recovery point testing
2. Backup retention management
3. Storage space monitoring
4. Integrity verification

## Support and Updates

### Update Process
1. Stop service
2. Backup database
3. Update Python script
4. Verify configuration
5. Restart service

### Health Checks
1. Database integrity
2. Recovery point validity
3. Component status
4. Resource usage

## Error Codes and Troubleshooting

### Common Error Codes
- 1001: Database connection failure
- 1002: Recovery point creation failed
- 1003: Component isolation error
- 1004: Registry backup failed
- 1005: WMI monitoring error

### Resolution Steps
Detailed for each error code in the logs with specific troubleshooting procedures and recovery steps.

<**Windows 11 Home - Insider Preview build Production 09/02/25**>
