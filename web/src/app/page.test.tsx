import { render, screen } from "@testing-library/react";

import HomePage from "@/app/page";

describe("landing page", () => {
  it("renders the hero thesis and correct primary actions", () => {
    render(<HomePage />);
    expect(
      screen.getByRole("heading", { name: /Every AI asset ships with a Birth Certificate/i }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "Verify an asset" })[0]).toHaveAttribute(
      "href",
      "/verify",
    );
    expect(screen.getByRole("link", { name: "View a Birth Certificate" })).toHaveAttribute(
      "href",
      "/verify#certificate-lookup",
    );
  });

  it("renders exactly the three locked product capabilities", () => {
    render(<HomePage />);
    for (const capability of ["Generate & Seal", "Birth Certificate", "Verify Gate"]) {
      expect(screen.getByRole("heading", { name: capability, level: 3 })).toBeInTheDocument();
    }
  });
});
