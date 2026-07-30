declare module "qrcode-svg" {
  interface QRCodeOptions {
    content: string;
    padding?: number;
    width?: number;
    height?: number;
    color?: string;
    background?: string;
    ecl?: "L" | "M" | "Q" | "H";
    join?: boolean;
    container?: "svg" | "svg-viewbox" | "g" | "none";
    pretty?: boolean;
    xmlDeclaration?: boolean;
  }

  export default class QRCode {
    constructor(options: string | QRCodeOptions);
    svg(): string;
  }
}
