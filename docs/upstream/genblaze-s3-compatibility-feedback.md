# genblaze-s3 compatibility feedback draft

This is a factual upstream issue draft. It has not been submitted.

## Summary

`genblaze-s3==0.3.6` declares `genblaze-core>=0.3.4,<0.4` and its public
`S3StorageBackend` contract works with `genblaze-core==0.3.8` on Python 3.12. The adapter currently
imports `genblaze_core._version` from `backend.py` and `_user_agent.py`. Would maintainers consider
using `importlib.metadata.version("genblaze-core")` or exposing a supported public version symbol?

The public `presigned_get()` operation also triggers `head_bucket`/region preflight even when the
backend was constructed with `preflight=False`. Some private-bucket applications need a purely
local signing path after configuration has already been validated separately.

This report is compatibility feedback, not a security claim or confirmed vulnerability.

## Minimal reproduction

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install `
  "genblaze-core==0.3.8" `
  "genblaze-s3==0.3.6" `
  "boto3==1.43.58"
```

```python
import os

os.environ["AWS_EC2_METADATA_DISABLED"] = "true"

from genblaze_core import KeyStrategy, ObjectStorageSink, StorageBackend
from genblaze_s3 import S3StorageBackend

backend = S3StorageBackend.for_backblaze(
    bucket="dummy-private-bucket",
    region="dummy-region",
    key_id="dummy-key-id",
    app_key="dummy-application-key",
    auto_lifecycle=False,
    preflight=False,
)
assert isinstance(backend, StorageBackend)
sink = ObjectStorageSink(backend, key_strategy=KeyStrategy.CONTENT_ADDRESSABLE)
sink.close()
```

Construction requires no real credentials and makes no storage request. Calling
`backend.presigned_get("example/object.bin")` subsequently attempts `head_bucket` before returning
the locally signed URL. A socket guard or a dummy `.invalid` region can demonstrate the attempted
preflight without contacting a real bucket.

Tested versions: Python 3.12, `genblaze-core==0.3.8`, `genblaze-s3==0.3.6`,
`boto3==1.43.58`, and `botocore==1.43.58`.
