export type User = {
  id: string;
  displayName: string;
  email: string;
  token: string;
  imageUrl?: string; // Using our SkillBridge domain name here!
}

export type LoginCreds = {
  email: string;
  password: string;
}

export type RegisterCreds = {
  displayName: string;
  email: string;
  password: string;
}