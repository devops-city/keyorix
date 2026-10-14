- **INV-SW-fence-open-without-holder** With no live holder the fence lets every write through, so a
  stopped or crashed server never blocks recovery. Guard: `TestFence_OpenWithoutALiveHolder`.
