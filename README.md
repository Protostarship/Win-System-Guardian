# SystemGuardian Service Documentation

## Overview
SystemGuardian is a Windows service designed to monitor and maintain system health by detecting, analyzing, and automatically responding to system events, registry issues, and component failures. The service provides proactive system maintenance through continuous monitoring, automatic repair attempts, and component isolation when necessary.

## Features
- Continuous monitoring of system event logs
- Registry health monitoring
- Automatic repair attempts for problematic components
- Component isolation for persistent issues
- User notifications for critical events
- Backup and recovery mechanisms
- Driver store management
- DCOM component monitoring

## Prerequisites

### System Requirements
- Windows Operating System
- Administrative privileges
- Python 3.6 or higher

### Required Python Packages
```
win32serviceutil
psutil
win10toast
```

### Required System Access
- Event Log access permissions
- Registry modification permissions
- Service management permissions
- Driver store access

## Installation

### Directory Structure
The service requires the following directory structure:
```
C:/ProgramData/ComponentMonitor/
├── config/
│   ├── event_patterns.json
│   ├── dependencies.json
│   ├── driver_map.json
│   └── backups/
├── logs/
└── quarantine/
```

### Configuration Files

#### event_patterns.json
```json
{
    "warnings": {
        "sources": ["Service Control Manager", "Disk", "Netwtw14"],
        "event_ids": [1001, 6062, 219]
    },
    "errors": {
        "sources": ["DCOM", "DriverFrameworks-UserMode", "Service Control Manager"],
        "event_ids": [10005, 10010, 7000, 7009]
    }
}
```

#### dependencies.json
Define component dependencies to manage cascading failures:
```json
{
    "component_name": ["dependent_component1", "dependent_component2"]
}
```

#### driver_map.json
Map driver information for recovery:
```json
{
    "driver_name": {
        "store_path": "path_in_driver_store",
        "backup_path": "backup_location"
    }
}
```

### Service Installation
1. Install the service using:
```bash
python SystemGuardian.py install
```

2. Start the service:
```bash
python SystemGuardian.py start
```

## Service Management

### Basic Commands
- Install: `python SystemGuardian.py install`
- Start: `python SystemGuardian.py start`
- Stop: `python SystemGuardian.py stop`
- Remove: `python SystemGuardian.py remove`
- Update: `python SystemGuardian.py update`

### Logging
- Logs are stored in `C:/ProgramData/ComponentMonitor/logs/guardian.log`
- Log format: `timestamp - level - message`
- Log levels: INFO, WARNING, ERROR

## Component Monitoring

### Event Log Monitoring
The service monitors system event logs for:
- Service failures
- Driver issues
- DCOM errors
- Hardware warnings
- System errors

### Registry Monitoring
Continuous monitoring of:
- Service registry entries
- Driver registry entries
- DCOM component registration
- Binary path validation

## Automatic Repair Mechanisms

### Service Repair
1. Automatic restart attempt
2. Registry validation
3. Binary path verification
4. Dependency check

### Driver Repair
1. Driver store backup check
2. Forced reinstallation
3. Registry cleanup
4. Quarantine management

### DCOM Repair
1. Registry key security
2. Component re-registration
3. Permission correction

## Component Isolation

### Isolation Triggers
- Maximum retry count exceeded
- Critical system errors
- Missing binaries
- Corrupted registry entries

### Isolation Process
1. Component shutdown
2. Registry backup
3. Configuration modification
4. User notification
5. Quarantine transfer (if applicable)

## Recovery and Backup

### Registry Backups
- Location: `C:/ProgramData/ComponentMonitor/config/backups/`
- Format: `.reg` files
- Naming: `component_type_name.reg`

### Driver Quarantine
- Location: `C:/ProgramData/ComponentMonitor/quarantine/`
- Original permissions preserved
- Metadata tracking

## Troubleshooting

### Common Issues

#### Service Won't Start
1. Check service account permissions
2. Verify directory permissions
3. Review event logs
4. Check configuration files

#### Component Isolation Failures
1. Verify administrative privileges
2. Check component dependencies
3. Review isolation logs
4. Verify backup locations

#### Registry Monitoring Issues
1. Check registry permissions
2. Verify registry paths
3. Review monitoring logs
4. Check security policies

### Log Analysis
1. Check `guardian.log` for error messages
2. Review Windows Event Viewer
3. Check component-specific logs
4. Analyze isolation queue entries

## Best Practices

### Configuration Management
1. Regular backup of configuration files
2. Version control for configuration changes
3. Documentation of custom patterns
4. Regular validation of dependencies

### Monitoring
1. Regular log review
2. Performance impact assessment
3. Resource usage monitoring
4. Alert threshold adjustment

### Security
1. Regular permission audits
2. Secure backup storage
3. Quarantine management
4. Access control maintenance

## Performance Considerations

### Resource Usage
- CPU: Minimal impact during normal operation
- Memory: ~50-100MB baseline
- Disk: Log rotation recommended
- Network: Minimal usage

### Optimization
1. Event pattern tuning
2. Monitoring interval adjustment
3. Log level management
4. Queue size limitations

## Support and Maintenance

### Regular Maintenance Tasks
1. Log rotation
2. Configuration review
3. Quarantine cleanup
4. Backup verification

### Update Process
1. Service stop
2. Configuration backup
3. File replacement
4. Service restart
5. Verification

### Health Checks
1. Service status verification
2. Log analysis
3. Resource usage monitoring
4. Component status review

## Security Considerations

### Access Control
- Service account minimal privileges
- Quarantine access restrictions
- Configuration file permissions
- Registry access controls

### Monitoring
- Failed repair attempts
- Unauthorized access attempts
- Configuration changes
- Component isolation events
