/*
 * Minecraft Forge
 * Copyright (c) 2018.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version 2.1
 * of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package net.minecraftforge.lex.redherring;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Random;

import org.apache.commons.io.IOUtils;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.InstructionAdapter;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiNewChat;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.client.network.NetHandlerPlayClient;
import net.minecraft.launchwrapper.IClassTransformer;
import net.minecraft.network.play.client.C19PacketResourcePackStatus;
import net.minecraft.network.play.client.C19PacketResourcePackStatus.Action;
import net.minecraft.network.play.server.S48PacketResourcePackSend;
import net.minecraft.util.ChatComponentText;
import net.minecraft.util.EnumChatFormatting;
import net.minecraftforge.fml.common.FMLLog;
import net.minecraftforge.fml.relauncher.FMLRelaunchLog;
import net.minecraftforge.fml.relauncher.IFMLLoadingPlugin;
import net.minecraftforge.fml.relauncher.IFMLLoadingPlugin.*;

/**
 * Simple, clean server resource pack "Exploit" fix.
 * The "Exploit" ONLY allows for the server to check if a file exists on the client or not.
 * And as a side effect cause the game to try and load the file as a resource pack.
 * There are currently no know issues with java's zip file management that would allow for any extra malicious activity.
 * So any claims of people being able to steal your passwords/execute code/etc.. is unfounded. Hence the name RedHerring.
 *
 * For more info refer to: https://ungeek.eu/minecraft-18-file-access/ Ignore the fear mongering bits like:
 * "Servers can check if a file exists on the player’s computer, enumerate users names … but maybe even worse. See PHP’s issue with file_exists and phar files."
 */
@Name("RedHerring")
@SortingIndex(1001)
public class RedHerring implements IFMLLoadingPlugin {
    private static Type NETHANDLERPLAYCLIENT = Type.getType("Lnet/minecraft/client/network/NetHandlerPlayClient;");
    private static Type RESOURCE_PACKET = Type.getType("Lnet/minecraft/network/play/server/S48PacketResourcePackSend;");

    @Override
    public String[] getASMTransformerClass() {
        return new String[] { getClass().getName() + "$Transformer" };
    }

    public static class Transformer implements IClassTransformer {
        @Override
        public byte[] transform(String name, String transformedName, byte[] basicClass) {
            if (!NETHANDLERPLAYCLIENT.getClassName().equals(transformedName))
                return basicClass;

            FMLRelaunchLog.info("[REDHERRING] Patching " + transformedName + "(" + name + ")");
            try {
                ClassNode node = getNode(basicClass);
                ClassNode inject = getNode(getBytes(RedHerring.class.getName() + "$Inject"));


                //Find the function to patch, I could hardcode the name in, but I don't feel like it. But we're looking for handle(S48PacketResourcePackSend)
                String desc = Type.getMethodDescriptor(Type.VOID_TYPE, RESOURCE_PACKET);
                for (MethodNode mtd : node.methods) {
                    if (mtd.desc.equals(desc)) {
                        FMLRelaunchLog.info("[REDHERRING] Patching Method " + transformedName + " " + mtd.name  + " " + desc);
                        //I make a new method node, and use InstructionAdapter so that I can easily build the if statement, I could of written it with InsnList directly, but this causes less verbose.
                        //I could of also used an external patching library, but why make it supper complex when we're doing something so stupid simple?
                        MethodNode _builder = new MethodNode();
                        InstructionAdapter ins = new InstructionAdapter(_builder);

                        // Build the new code: if (_areTheyNaughty(this, pkt)) return;
                        Label safe = new Label();
                        ins.load(0, NETHANDLERPLAYCLIENT);
                        ins.load(1, RESOURCE_PACKET);
                        ins.invokestatic(NETHANDLERPLAYCLIENT.getInternalName(), "_areTheyNaughty", Type.getMethodDescriptor(Type.BOOLEAN_TYPE, NETHANDLERPLAYCLIENT, RESOURCE_PACKET), false);
                        ins.ifeq(safe);
                        ins.areturn(Type.VOID_TYPE);
                        ins.mark(safe);

                        // Add it to the start of the function so we can short circuit if they are naughty!
                        mtd.instructions.insertBefore(mtd.instructions.getFirst(), _builder.instructions);
                    }
                }

                //Again, I COULD of used some super complex external patching library to copy this code into the vanilla class. But seriously it all boils down to adding a new method node... so why make it complex?
                for (MethodNode mtd : inject.methods) {
                    if (mtd.name.startsWith("_")) {
                        FMLRelaunchLog.info("[REDHERRING] Injecting Method " + mtd.name  + " " + mtd.desc);
                        node.methods.add(mtd);
                    }
                }

                return getBytes(node);
            } catch (IOException e) {
                FMLRelaunchLog.info("[REDHERRING] Could not patch NetHandlerPlayClient: " + e.getMessage());
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }

        //Just some utility methods, byte[] <-> ClassNode and reading a resources bytes. Again stupid simple why add massive external deps?
        private ClassNode getNode(byte[] data) {
            ClassNode classNode = new ClassNode();
            ClassReader classReader = new ClassReader(data);
            classReader.accept(classNode, 0);
            return classNode;
        }

        private byte[] getBytes(ClassNode node) {
            ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
            node.accept(writer);
            return writer.toByteArray();
        }

        private byte[] getBytes(String cls) throws IOException {
            try (InputStream input = RedHerring.class.getResourceAsStream("/" + cls.replace('.', '/') + ".class")) {
                return IOUtils.toByteArray(input);
            }
        }
    }

    public static class Inject {
        /**
         * Now, the actual core of this change. The basic idea is that Mojang special cases the "level://" prefix, to specify a existing resource pack on the clients machine.
         * This is all fine and dandy, but they didn't check for directory navigation, so the server COULD to to load level://../../../MySuperSecret/Pron/Folder.zip as a resource pack.
         * The server would get a response back if that file exists, and then get another response if it was able to load it as a zip/resource pack.
         * Now, does this let the server know the CONTENTS of the file? WITHOUT QUESTION THIS IS A NO.
         * Does this let the server execute random code? No.
         * Does this let the server walk into your house, and kick your dog? Nope. The little bugger is safe.
         *
         * All this lets them do is check if a file exists. Now, why is this important? A hypothetical scenario is that they can passively scan for files that might indicate OTHER exploits exist.
         * Like looking at the default install folder for a web server, and seeing if its there. If it is it could indicate that they should run an external scan on your IP for web servers.
         *
         * Now, has there been any reported cases of this? No. And honestly brute forcing a list of file checks isn't a very efficient way to find an exploit. But hey people are harping on this
         * as some end of the world thing. So here I am, wasting my time, writing this thing...
         */
        public static boolean _areTheyNaughty(NetHandlerPlayClient handler, S48PacketResourcePackSend pkt) {
            ServerData data = Minecraft.getMinecraft().getCurrentServerData();
            //Now, THIS bit is actually important. If you've ever clicked the "Accept" button for a resource pack download, Minecraft remembers that option.
            //And auto accepts the next time on the same server. This changes that to prompt every time.
            //This way the user knows exactly when a file is being downloaded and from what URL.
            //How can this be exploited? Well if they can drop a file on to your computer. And then some other process comes along and messes with that file. Things can get nasty.
            //There have been a few cases, but an example, is that in the past there was a commonly used image editor. That has a bug where a malformed image could run arbitrary code when the
            //image editor tried to render the thumbnail of a malicious image.
            if (data.getResourceMode() == ServerData.ServerResourceMode.ENABLED) { //Don't let the server auto-download files to my computer! Even if the user is stupid.
                data.setResourceMode(ServerData.ServerResourceMode.PROMPT);
            }

            //Lets add a debug message for all resource packs, just to keep track.
            String server = handler.getNetworkManager().getRemoteAddress().toString();
            FMLLog.warning("[REDHERRING] Requested Resource Pack. Server: " + server + " URL: " + pkt.getURL() + " Hash: " + pkt.getHash());

            boolean naughty = false;
            try {
                URI uri = new URI(pkt.getURL());
                //Now, if its a level:// url and it has a ".." which is a potential directory traversal, then its naughty. The resources.zip is just a check cuz 1.9 added it to.
                naughty = uri.getScheme().equals("level") && (pkt.getURL().contains("..") || !pkt.getURL().endsWith("/resources.zip"));
            } catch (URISyntaxException e) {
                naughty = true;
            }

            if (!naughty)
                return false;

            //Now that we know they were naughty, lets poke the file they were trying to check and see if it does exist. And print out the warnings.
            File target = new File(new File(Minecraft.getMinecraft().mcDataDir, "saves"), pkt.getURL().substring(8));
            Action def = target.isFile() ? Action.ACCEPTED : Action.FAILED_DOWNLOAD;
            Action _new = Action.values()[new Random().nextInt(Action.values().length)];

            GuiNewChat chat = Minecraft.getMinecraft().ingameGUI.getChatGUI();
            FMLLog.warning("[REDHERRING] Server attempted to load invalid resource pack: " + pkt.getURL() + " Hash: " + pkt.getHash());
            FMLLog.warning("[REDHERRING] Old Response: " + def.name() + " New Response: " + _new.name());
            chat.printChatMessage(new ChatComponentText(EnumChatFormatting.RED + "[REDHERRING] Server attempted to load invalid resource pack: " + pkt.getURL() + " Hash: " + pkt.getHash()));
            chat.printChatMessage(new ChatComponentText(EnumChatFormatting.RED + "[REDHERRING] Old Response: " + def.name() + " New Response: " + _new.name()));

            //Send the random response back, because it's funny.
            handler.addToSendQueue(new C19PacketResourcePackStatus(pkt.getHash(),_new));

            return true;
        }
    }

    @Override public String getModContainerClass() { return null; }
    @Override public String getSetupClass() { return null; }
    @Override public void injectData(Map<String, Object> data) {}
    @Override public String getAccessTransformerClass() { return null; }
}
