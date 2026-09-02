import { describe, expect, it } from "vitest";
import { duration, operationLabel, percent, shortSHA } from "./present";

describe("presentation boundaries", () => {
  it("formats bounded operational values", () => {
    expect(shortSHA("0123456789abcdef0123456789abcdef01234567")).toBe("01234567");
    expect(duration(125)).toBe("2m 5s");
    expect(percent(8734)).toBe("87.3%");
  });

  it("does not present unknown operations as valid", () => {
    expect(operationLabel("workflow_dispatch")).toBe("Unsupported operation");
  });
});
