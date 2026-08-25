export type ClassValue = string | number | null | undefined | false;

export function cx(...values: ClassValue[]): string {
  return values.filter(Boolean).join(" ");
}
