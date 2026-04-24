```bash
touch readonly
sudo mount --bind readonly rootfs/readonly
sudo mount -o remount,bind,ro rootfs/readonly
```