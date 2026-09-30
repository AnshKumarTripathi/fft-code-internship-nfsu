export function AlertApiDown() {
  return (
    <div role="alert" className="alert alert-error">
      <span>
        The JSON API is not running. From <code>code/</code>, start{" "}
        <code>uvicorn src.api.main:app --host 127.0.0.1 --port 8000</code>.
      </span>
    </div>
  );
}
