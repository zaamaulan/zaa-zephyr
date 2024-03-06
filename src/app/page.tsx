import { getServerSession } from "next-auth";
import React from "react";
import { authOptions } from "./api/auth/[...nextauth]/route";

const page = async () => {
  const session = await getServerSession(authOptions);
  console.log(session);

  return <div>page</div>;
};

export default page;
