/// <reference types="vite/client" />

// Declare CSS modules for Vite
declare module '*.css' {
  const content: Record<string, string>;
  export default content;
}

// Declare other asset types
declare module '*.svg' {
  import type { ReactComponent } from 'react';
  export const ReactComponent: React.FC<React.SVGProps<SVGSVGElement>>;
  const src: string;
  export default src;
}

declare module '*.png' {
  const content: string;
  export default content;
}

declare module '*.jpg' {
  const content: string;
  export default content;
}

declare module '*.jpeg' {
  const content: string;
  export default content;
}

declare module '*.gif' {
  const content: string;
  export default content;
}

declare module '*.webp' {
  const content: string;
  export default content;
}
