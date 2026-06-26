# Project Manifest

Application projects do not live inside this repository. They are attached through manifest metadata, runtime configuration, digest-pinned images and release evidence.

## Supported runtime classes

- `static`
- `node`
- `php`
- `python`
- `docker-custom`
- `worker`
- `cron`

## Minimal manifest shape

```json
{
  "version": 1,
  "project": {
    "id": "client-portal",
    "name": "Client Portal",
    "runtime": "node"
  },
  "releaseImages": [
    {
      "key": "APP_IMAGE",
      "name": "app",
      "image": "registry.example.com/client-portal/app:1.0.0@sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }
  ]
}
```

## Hosts

Use explicit host metadata per project. Examples:

- `client-portal.apps.example.com`
- `node-demo.example.com`
- `php-demo.example.com`
- `worker-demo.example.com`

Do not use the Control Center host as a project host.

## Release subjects

Every deployable image should be digest-pinned. Release evidence may contain any number of image subjects, SBOMs and rollback targets.

## Rollback

Rollback metadata should identify the previous image set and the command or workflow used to restore it.
